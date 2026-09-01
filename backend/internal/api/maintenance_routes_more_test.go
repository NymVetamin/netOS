package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/tlsutil"
)

func TestPanelMaintenanceCreatesIsolatedRevisionAndSchedulesRollbackGuard(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	current := initializeAPIEngine(t, s)
	previousID, err := s.Store.CreateRevision(current, "system", "active")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.MarkActive(previousID); err != nil {
		t.Fatal(err)
	}
	runner := &maintenanceRouteRunner{}
	s.Maintenance = &Maintenance{Runner: runner, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	oldTimeout := panelActivationStaleAfter
	panelActivationStaleAfter = 0
	defer func() { panelActivationStaleAfter = oldTimeout }()

	port := freeTCPPort(t)
	body := fmt.Sprintf(`{"panel":{"port":%d,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"RESTART"}`, port)
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", []byte(body), cookie, csrf)
	if w.Code != http.StatusAccepted {
		t.Fatalf("panel maintenance status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Revision int64 `json:"revision"`
		Port     int   `json:"port"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Revision < 1 || response.Port != port {
		t.Fatalf("response=%+v", response)
	}
	target, err := s.Store.Revision(response.Revision)
	if err != nil || target.State != "applying" || target.Config.System.Panel.Port != port {
		t.Fatalf("target=%+v err=%v", target, err)
	}
	var panelRulePort string
	for _, rule := range target.Config.Firewall.Rules {
		if rule.ID == "sys-panel" {
			panelRulePort = rule.DstPort
		}
	}
	if panelRulePort != fmt.Sprint(port) {
		t.Fatalf("target panel firewall port=%q", panelRulePort)
	}
	if current.System.Panel.Port != 8443 {
		t.Fatalf("engine current config mutated to port %d", current.System.Panel.Port)
	}
	commands := strings.Join(runner.commands, "\n")
	want := fmt.Sprintf("/usr/local/bin/netos internal-panel-activate %d %d", response.Revision, previousID)
	if !strings.Contains(commands, want) {
		t.Fatalf("schedule command missing %q:\n%s", want, commands)
	}
}

func TestPanelMaintenanceRequiresAdminSessionAndCSRF(t *testing.T) {
	s, adminCookie, adminCSRF := newAuthedServer(t)
	h := s.Routes()
	body := []byte(`{"panel":{"port":8443,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"RESTART"}`)
	if w := serveAuthed(h, http.MethodPost, "/api/maintenance/panel", body, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", w.Code, w.Body.String())
	}
	if w := serveAuthed(h, http.MethodPost, "/api/maintenance/panel", body, adminCookie, "wrong"); w.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF status=%d body=%s", w.Code, w.Body.String())
	}
	viewerHash, err := HashPassword("viewer-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateUser("panel-viewer", viewerHash, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateSession("panel-viewer-session", "panel-viewer", "127.0.0.2", time.Hour); err != nil {
		t.Fatal(err)
	}
	s.csrfMu.Lock()
	s.csrfTokens["panel-viewer-session"] = "panel-viewer-csrf"
	s.csrfMu.Unlock()
	viewerCookie := &http.Cookie{Name: sessionCookie, Value: "panel-viewer-session"}
	if w := serveAuthed(h, http.MethodPost, "/api/maintenance/panel", body, viewerCookie, "panel-viewer-csrf"); w.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d body=%s", w.Code, w.Body.String())
	}
	if adminCSRF == "" {
		t.Fatal("admin fixture did not issue CSRF token")
	}
}

func TestPanelMaintenanceRejectsUnsafeOrConflictingRequests(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	current := initializeAPIEngine(t, s)
	previousID, err := s.Store.CreateRevision(current, "system", "active")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.MarkActive(previousID); err != nil {
		t.Fatal(err)
	}
	s.Maintenance = &Maintenance{Runner: &maintenanceRouteRunner{}, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"confirmation", `{"panel":{"port":8443,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"wrong"}`, http.StatusBadRequest},
		{"invalid port", `{"panel":{"port":0,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"RESTART"}`, http.StatusUnprocessableEntity},
		{"incomplete ACME", `{"panel":{"port":8443,"commit_timeout":30,"tls":{"mode":"acme","domain":"router.acme-valid.com"}},"confirm":"RESTART"}`, http.StatusUnprocessableEntity},
		{"missing custom pair", `{"panel":{"port":8443,"commit_timeout":30,"tls":{"mode":"custom","cert_file":"/missing.crt","key_file":"/missing.key"}},"confirm":"RESTART"}`, http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", []byte(tc.body), cookie, csrf)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
	oldPortAvailable := panelPortAvailable
	panelPortAvailable = func(port int) error {
		if port != 9443 {
			t.Fatalf("probed port=%d", port)
		}
		return fmt.Errorf("injected occupied port")
	}
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", []byte(`{"panel":{"port":9443,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"RESTART"}`), cookie, csrf)
	panelPortAvailable = oldPortAvailable
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "9443") {
		t.Fatalf("occupied port status=%d body=%s", w.Code, w.Body.String())
	}
	s.draftMu.Lock()
	s.draft = current
	s.draftMu.Unlock()
	w = serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", []byte(`{"panel":{"port":8443,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"RESTART"}`), cookie, csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("dirty draft status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPanelMaintenanceAcceptsCompleteACMEAndPreflightsHTTPPort(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	current := initializeAPIEngine(t, s)
	previousID, err := s.Store.CreateRevision(current, "system", "active")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.MarkActive(previousID); err != nil {
		t.Fatal(err)
	}
	s.Maintenance = &Maintenance{Runner: &maintenanceRouteRunner{}, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	oldAvailable := panelPortAvailable
	defer func() { panelPortAvailable = oldAvailable }()
	var probes []int
	panelPortAvailable = func(port int) error { probes = append(probes, port); return nil }
	oldTimeout := panelActivationStaleAfter
	panelActivationStaleAfter = 0
	defer func() { panelActivationStaleAfter = oldTimeout }()
	body := []byte(`{"panel":{"port":8443,"commit_timeout":30,"tls":{"mode":"acme","domain":"router.acme-valid.com","email":"admin@example.org","accept_tos":true}},"confirm":"RESTART"}`)
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", body, cookie, csrf)
	if w.Code != http.StatusAccepted || len(probes) != 1 || probes[0] != 80 {
		t.Fatalf("ACME status=%d probes=%v body=%s", w.Code, probes, w.Body.String())
	}
	revisions, err := s.Store.ListRevisions(2)
	if err != nil || len(revisions) < 1 {
		t.Fatalf("ACME revision=%+v err=%v", revisions, err)
	}
	prepared, err := s.Store.Revision(revisions[0].ID)
	if err != nil || prepared.Config.System.Panel.TLS.Domain != "router.acme-valid.com" || !prepared.Config.System.Panel.TLS.AcceptTOS {
		t.Fatalf("prepared ACME revision=%+v err=%v", prepared, err)
	}

	// A foreign listener on port 80 is rejected before a revision is prepared.
	s2, cookie2, csrf2 := newAuthedServer(t)
	current2 := initializeAPIEngine(t, s2)
	id2, _ := s2.Store.CreateRevision(current2, "system", "active")
	_ = s2.Store.MarkActive(id2)
	s2.Maintenance = &Maintenance{Runner: &maintenanceRouteRunner{}, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	panelPortAvailable = func(port int) error { return fmt.Errorf("occupied %d", port) }
	w = serveAuthed(s2.Routes(), http.MethodPost, "/api/maintenance/panel", body, cookie2, csrf2)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "80") {
		t.Fatalf("occupied ACME HTTP status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPanelMaintenanceAcceptsRealCustomCertificatePair(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	current := initializeAPIEngine(t, s)
	previousID, err := s.Store.CreateRevision(current, "system", "active")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.MarkActive(previousID); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, key, _, err := tlsutil.EnsureSelfSigned(dir, "router.test")
	if err != nil {
		t.Fatal(err)
	}
	otherDir := t.TempDir()
	_, otherKey, _, err := tlsutil.EnsureSelfSigned(otherDir, "other.test")
	if err != nil {
		t.Fatal(err)
	}
	runner := &maintenanceRouteRunner{}
	s.Maintenance = &Maintenance{Runner: runner, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	oldTimeout := panelActivationStaleAfter
	panelActivationStaleAfter = 0
	defer func() { panelActivationStaleAfter = oldTimeout }()
	mismatchedBody, err := json.Marshal(map[string]any{
		"panel": map[string]any{
			"port": 8443, "commit_timeout": 30,
			"tls": map[string]any{"mode": "custom", "cert_file": cert, "key_file": otherKey},
		},
		"confirm": "RESTART",
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", mismatchedBody, cookie, csrf); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched TLS status=%d body=%s", w.Code, w.Body.String())
	}
	body, err := json.Marshal(map[string]any{
		"panel": map[string]any{
			"port": 8443, "commit_timeout": 30,
			"tls": map[string]any{"mode": "custom", "cert_file": cert, "key_file": key},
		},
		"confirm": "RESTART",
	})
	if err != nil {
		t.Fatal(err)
	}
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", body, cookie, csrf)
	if w.Code != http.StatusAccepted {
		t.Fatalf("custom TLS status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPanelMaintenanceScheduleFailureRollsBackPreparedRevisionAndUnlocksDraft(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	current := initializeAPIEngine(t, s)
	previousID, err := s.Store.CreateRevision(current, "system", "active")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.MarkActive(previousID); err != nil {
		t.Fatal(err)
	}
	s.Maintenance = &Maintenance{Runner: &maintenanceRouteRunner{fail: "systemd-run"}, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	body := []byte(`{"panel":{"port":8443,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"RESTART"}`)
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", body, cookie, csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("schedule failure status=%d body=%s", w.Code, w.Body.String())
	}
	s.draftMu.RLock()
	locked := s.draftApplying
	s.draftMu.RUnlock()
	if locked {
		t.Fatal("failed schedule left draft locked")
	}
	revisions, err := s.Store.ListRevisions(10)
	if err != nil || len(revisions) < 2 || revisions[0].State != "rolled_back" {
		t.Fatalf("revisions=%+v err=%v", revisions, err)
	}
}

func TestPanelMaintenanceStaleScheduleUnlocksOldDaemon(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	current := initializeAPIEngine(t, s)
	previousID, err := s.Store.CreateRevision(current, "system", "active")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.MarkActive(previousID); err != nil {
		t.Fatal(err)
	}
	s.Maintenance = &Maintenance{Runner: &maintenanceRouteRunner{}, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	oldTimeout := panelActivationStaleAfter
	panelActivationStaleAfter = 5 * time.Millisecond
	defer func() { panelActivationStaleAfter = oldTimeout }()
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", []byte(`{"panel":{"port":8443,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"RESTART"}`), cookie, csrf)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.draftMu.RLock()
		locked := s.draftApplying
		s.draftMu.RUnlock()
		if !locked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	s.draftMu.RLock()
	locked := s.draftApplying
	s.draftMu.RUnlock()
	revision, revErr := s.Store.Revision(response.Revision)
	if locked || revErr != nil || revision.State != "rolled_back" {
		t.Fatalf("locked=%v revision=%+v err=%v", locked, revision, revErr)
	}
}

type maintenanceRouteRunner struct {
	active   bool
	fail     string
	commands []string
}

func (r *maintenanceRouteRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if strings.Contains(command, r.fail) && r.fail != "" {
		return "", fmt.Errorf("injected %s failure", r.fail)
	}
	if name == "systemctl" && len(args) > 0 {
		switch args[0] {
		case "is-active":
			if r.active {
				return "active\ninactive\n", nil
			}
			return "inactive\ninactive\n", nil
		case "show":
			return "ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=17\n", nil
		}
	}
	return "", nil
}

func (r *maintenanceRouteRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestMaintenanceRoutesCompleteLifecycle(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	dir := t.TempDir()
	name := "netos-backup-20260901-120000.tar.gz"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("archive-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Maintenance = &Maintenance{Runner: &maintenanceRouteRunner{}, BackupDir: dir, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	h := s.Routes()

	for _, tc := range []struct {
		method string
		path   string
		body   string
		want   int
	}{
		{http.MethodGet, "/api/maintenance/status", "", http.StatusOK},
		{http.MethodGet, "/api/backups", "", http.StatusOK},
		{http.MethodGet, "/api/backups/" + name, "", http.StatusOK},
		{http.MethodPost, "/api/backups", "", http.StatusAccepted},
		{http.MethodPost, "/api/maintenance/restore", `{"name":"` + name + `","confirm":"RESTORE"}`, http.StatusAccepted},
		{http.MethodPost, "/api/maintenance/update", `{"version":"v1.2.3","confirm":"UPDATE"}`, http.StatusAccepted},
		{http.MethodPost, "/api/maintenance/restore", `{"name":"` + name + `","confirm":"wrong"}`, http.StatusBadRequest},
		{http.MethodPost, "/api/maintenance/update", `{"version":"v1;reboot","confirm":"UPDATE"}`, http.StatusConflict},
	} {
		w := serveAuthed(h, tc.method, tc.path, []byte(tc.body), cookie, csrf)
		if w.Code != tc.want {
			t.Fatalf("%s %s status=%d want=%d body=%s", tc.method, tc.path, w.Code, tc.want, w.Body.String())
		}
		if tc.path == "/api/backups/"+name && tc.method == http.MethodGet && w.Body.String() != "archive-data" {
			t.Fatalf("download body=%q", w.Body.String())
		}
	}

	w := serveAuthed(h, http.MethodDelete, "/api/backups/"+name, nil, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatalf("backup still exists: %v", err)
	}
	if w := serveAuthed(h, http.MethodGet, "/api/backups/"+name, nil, cookie, ""); w.Code != http.StatusNotFound {
		t.Fatalf("deleted download status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestNewMaintenanceDefaults(t *testing.T) {
	runner := &maintenanceRouteRunner{}
	m := NewMaintenance(runner)
	if m.Runner != runner || m.BackupDir != "/var/backups/netos" || m.Binary != "/usr/local/bin/netos" || m.Unit != "netos-maintenance" {
		t.Fatalf("defaults=%+v", m)
	}
}

func TestMaintenanceRoutesBusyFailureAndUnavailable(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	s.Maintenance = &Maintenance{Runner: &maintenanceRouteRunner{active: true}, BackupDir: t.TempDir(), Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	if w := serveAuthed(s.Routes(), http.MethodPost, "/api/backups", nil, cookie, csrf); w.Code != http.StatusConflict {
		t.Fatalf("busy backup status=%d body=%s", w.Code, w.Body.String())
	}
	s.Maintenance.Runner = &maintenanceRouteRunner{fail: "systemd-run"}
	if w := serveAuthed(s.Routes(), http.MethodPost, "/api/backups", nil, cookie, csrf); w.Code != http.StatusConflict {
		t.Fatalf("schedule failure status=%d body=%s", w.Code, w.Body.String())
	}
	s.Maintenance = nil
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/backups", ""},
		{http.MethodGet, "/api/backups/netos-x.tar.gz", ""},
		{http.MethodPost, "/api/backups", ""},
		{http.MethodDelete, "/api/backups/netos-x.tar.gz", ""},
		{http.MethodPost, "/api/maintenance/restore", `{"name":"netos-x.tar.gz","confirm":"RESTORE"}`},
		{http.MethodPost, "/api/maintenance/update", `{"version":"latest","confirm":"UPDATE"}`},
	} {
		w := serveAuthed(s.Routes(), tc.method, tc.path, []byte(tc.body), cookie, csrf)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}

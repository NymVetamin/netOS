//go:build linux

package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationLoginStorageFull(t *testing.T) {
	if os.Getenv("NETOS_LOGIN_STORAGE_FULL") != "1" {
		t.Skip("requires authorized root Linux tmpfs mount")
	}
	root := t.TempDir()
	old := initialCredentialsPath
	initialCredentialsPath = filepath.Join(root, "absent")
	defer func() { initialCredentialsPath = old }()
	if err := syscall.Mount("tmpfs", root, "tmpfs", 0, "size=4m,mode=0700"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Unmount(root, 0); err != nil {
			t.Error(err)
		}
	}()
	st, err := store.Open(filepath.Join(root, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	hash, err := HashPassword("test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.CreateUser("admin", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	logger := &lifecycleLogger{}
	s := &Server{Store: st, Logger: logger, loginFails: map[string]*failCounter{}, loginSlots: make(chan struct{}, maxConcurrentLogins), csrfTokens: map[string]string{}}
	filler := filepath.Join(root, "fill")
	f, err := os.Create(filler)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 65536)
	for written := 0; written < 8<<20; written += len(block) {
		_, err = f.Write(block)
		if err != nil {
			break
		}
	}
	f.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatal("filesystem not full", err)
	}
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"test-password-123"}`))
		r.RemoteAddr = "192.0.2.1:1000"
		w := httptest.NewRecorder()
		s.handleLogin(w, r)
		return w
	}
	w := request()
	if w.Code != 507 || len(w.Result().Cookies()) != 0 || len(logger.lines) != 1 {
		t.Fatal("full rejection", w.Code, len(logger.lines))
	}
	entry := logEntry{Unit: "netosd.service", Message: "[инфо] " + logger.lines[0]}
	if !panelJournalFields(&entry) || !strings.Contains(entry.Message, `"reason":"session-full"`) || entry.Result != "failure" {
		t.Fatal(entry)
	}
	if rows, err := st.ListAccessAudit(context.Background(), 100); err != nil || len(rows) != 0 {
		t.Fatal("false success", rows, err)
	}
	if err = os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	w = request()
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || len(logger.lines) != 1 {
		t.Fatal("retry", w.Code, len(logger.lines))
	}
	if rows, err := st.ListAccessAudit(context.Background(), 100); err != nil || len(rows) != 1 || !rows[0].Success {
		t.Fatal("retry audit", rows, err)
	}
	t.Log("real tmpfs ENOSPC: HTTP507, failure event, no cookie; released space: HTTP200, one SQL success, no duplicate")
}

func TestIntegrationPanelStorageJournal(t *testing.T) {
	if os.Getenv("NETOS_STORAGE_JOURNAL_INTEGRATION") != "1" {
		t.Skip("requires authorized Linux without installed netosd unit")
	}
	run := &system.Exec{Timeout: time.Minute, MaxOutputBytes: 4 << 20}
	ctx := context.Background()
	state, err := run.Run(ctx, "systemctl", "show", "netosd.service", "--property=LoadState", "--value")
	if err != nil || strings.TrimSpace(state) != "not-found" {
		t.Fatal("refusing to replace existing unit", state, err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	from := time.Now().Add(-time.Second).UTC()
	t.Cleanup(func() {
		run.Run(ctx, "systemctl", "stop", "netosd.service")
		run.Run(ctx, "systemctl", "reset-failed", "netosd.service")
	})
	if out, err := run.Run(ctx, "systemd-run", "--unit=netosd.service", "--wait", "--collect", "--property=StandardOutput=journal", "--property=StandardError=journal", "--setenv=NETOS_STORAGE_JOURNAL_CHILD=1", binary, "-test.run=^(TestLoginStorageFailureFallbackAndRetry|TestLoginReadFailureReasonAndRetry)$", "-test.v"); err != nil {
		t.Fatal(out, err)
	}
	if out, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
		t.Fatal(out, err)
	}
	period := "from=" + url.QueryEscape(from.Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(time.Now().UTC().Format(time.RFC3339Nano))
	st, err := store.Open(filepath.Join(t.TempDir(), "read.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{Store: st, StorageRunner: run}
	page := readAllJournalPages(t, s, "access", period+"&object=panel")
	if len(page.Entries) != 5 {
		t.Fatal("missing fallback", len(page.Entries))
	}
	success := 0
	for _, e := range page.Entries {
		if e.Severity != "warning" || e.User != "admin" || e.Address != "192.0.2.1" {
			t.Fatal(e)
		}
		if e.Result == "success" {
			success++
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	all, code := allPageRequest(t, s, filepath.Join(t.TempDir(), "dns.log"), period+"&object="+url.QueryEscape(panelLoginMarker)+"&result=warning")
	if code != 200 || len(all.Entries) != 5 {
		t.Fatal(code, len(all.Entries))
	}
	services := readAllJournalPages(t, s, "services", period)
	for _, e := range services.Entries {
		if strings.Contains(e.Message, panelLoginMarker) {
			t.Fatal("service duplicate")
		}
	}
	t.Log("actual storage failures -> netosd stderr -> journald -> Access/General warnings; Services excludes fallback: PASS")
}

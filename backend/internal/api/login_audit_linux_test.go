//go:build linux

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/system"
)

type panelJournalTestLogger struct{ logger *log.Logger }

func (l panelJournalTestLogger) Infof(f string, a ...any)  { l.logger.Printf("[инфо] "+f, a...) }
func (l panelJournalTestLogger) Warnf(f string, a ...any)  { l.logger.Printf("[пред] "+f, a...) }
func (l panelJournalTestLogger) Errorf(f string, a ...any) { l.logger.Printf("[ошиб] "+f, a...) }

func TestPanelAuditJournalChild(t *testing.T) {
	if os.Getenv("NETOS_PANEL_AUDIT_CHILD") != "1" {
		t.Skip("invoked by authorized transient unit")
	}
	path := filepath.Join(t.TempDir(), "locked-audit.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	conn, err := writer.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	s := &Server{Store: st, loginFails: map[string]*failCounter{}, loginSlots: make(chan struct{}, maxConcurrentLogins)}
	s.Logger = panelJournalTestLogger{log.New(os.Stderr, "", log.LstdFlags)}
	server := httptest.NewServer(http.HandlerFunc(s.handleLogin))
	defer server.Close()
	var maxElapsed time.Duration
	for _, tc := range []struct {
		body          string
		status        int
		blocked, busy bool
	}{
		{`{"username":`, 400, false, false},
		{`{"username":"admin","password":"secret"` + strings.Repeat(" ", maxLoginBodyBytes) + `}`, 400, false, false},
		{`{"username":"","password":"secret"}`, 401, false, false},
		{`{"username":"admin","password":"` + strings.Repeat("x", maxPasswordBytes+1) + `"}`, 401, false, false},
		{`{"username":"admin","password":"secret"}`, 429, true, false},
		{`{"username":"admin","password":"secret"}`, 429, false, true},
	} {
		if tc.blocked {
			s.loginMu.Lock()
			s.loginFails["127.0.0.1"] = &failCounter{count: 6, last: time.Now(), until: time.Now().Add(time.Minute)}
			s.loginMu.Unlock()
		}
		if tc.busy {
			for n := 0; n < maxConcurrentLogins; n++ {
				s.loginSlots <- struct{}{}
			}
		}
		req, _ := http.NewRequest("POST", server.URL, strings.NewReader(tc.body))
		req.Header.Set("X-Forwarded-For", "198.51.100.1")
		start := time.Now()
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		maxElapsed = max(maxElapsed, time.Since(start))
		if response.StatusCode != tc.status {
			t.Fatal(response.StatusCode, tc.status)
		}
		if tc.blocked {
			s.clearLoginFailures("127.0.0.1")
		}
		if tc.busy {
			for n := 0; n < maxConcurrentLogins; n++ {
				<-s.loginSlots
			}
		}
	}
	for n := 0; n < 1000; n++ {
		start := time.Now()
		response, err := server.Client().Post(server.URL, "application/json", strings.NewReader(`{"username":`))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		maxElapsed = max(maxElapsed, time.Since(start))
		if response.StatusCode != 400 {
			t.Fatal(response.StatusCode)
		}
	}
	if maxElapsed > 2*time.Second {
		t.Fatal("early HTTP rejection waited for the SQLite writer", maxElapsed)
	}
	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Store.ListAccessAudit(context.Background(), 100)
	if err != nil || len(rows) != 0 {
		t.Fatal("early path wrote SQL", len(rows), err)
	}
}

func TestIntegrationPanelLoginAudit(t *testing.T) {
	if os.Getenv("NETOS_PANEL_AUDIT_INTEGRATION") != "1" {
		t.Skip("requires authorized Linux with netosd unit absent")
	}
	run := &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	ctx := context.Background()
	state, err := run.Run(ctx, "systemctl", "show", "netosd.service", "--property=LoadState", "--value")
	if err != nil || strings.TrimSpace(state) != "not-found" {
		t.Fatal("refusing to replace existing netosd unit", state, err)
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
	launcher := &system.Exec{Timeout: time.Minute, MaxOutputBytes: 4 << 20}
	if out, err := launcher.Run(ctx, "systemd-run", "--unit=netosd.service", "--wait", "--collect", "--property=StandardOutput=journal", "--property=StandardError=journal", "--setenv=NETOS_PANEL_AUDIT_CHILD=1", binary, "-test.run=^TestPanelAuditJournalChild$", "-test.v"); err != nil {
		t.Fatal(out, err)
	}
	if out, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
		t.Fatal(out, err)
	}
	to := time.Now().UTC()
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{Store: st, StorageRunner: run}
	period := "from=" + url.QueryEscape(from.Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(to.Format(time.RFC3339Nano))
	access := readAllJournalPages(t, s, "access", period+"&object=panel")
	if len(access.Entries) != earlyLoginLimit+1 {
		t.Fatal("missing native events", len(access.Entries))
	}
	notices := 0
	for _, e := range access.Entries {
		if e.Protocol != "panel" || e.Unit != "netosd.service" || strings.Contains(e.Message, "secret") || strings.Contains(e.Message, "198.51.100.1") {
			t.Fatal("invalid native event", e.ID)
		}
		if e.Result == "info" {
			notices++
			if e.Address != "" {
				t.Fatal("notice attributed to peer")
			}
		} else if e.Address != "127.0.0.1" {
			t.Fatal("wrong source", e.Address)
		}
	}
	if notices != 1 {
		t.Fatal(notices)
	}
	all, code := allPageRequest(t, s, filepath.Join(t.TempDir(), "dns.log"), period+"&object="+url.QueryEscape(panelLoginMarker))
	if code != 200 || all.Next != "" || len(all.Entries) != len(access.Entries) {
		t.Fatal(code, len(all.Entries), all.Next)
	}
	for _, e := range all.Entries {
		if e.Source != "access" {
			t.Fatal("misclassified", e.Source)
		}
	}
	services := readAllJournalPages(t, s, "services", period)
	for _, e := range services.Entries {
		if strings.Contains(e.Message, panelLoginMarker) {
			t.Fatal("panel event leaked into services")
		}
	}
	warnings, code := allPageRequest(t, s, filepath.Join(t.TempDir(), "dns.log"), period+"&object="+url.QueryEscape(panelLoginMarker)+"&result=warning")
	if code != 200 || len(warnings.Entries) != 1 || warnings.Entries[0].Result != "info" {
		t.Fatal("limit notice missing from warnings", code, len(warnings.Entries))
	}
	if output := os.Getenv("NETOS_PANEL_AUDIT_OUTPUT"); output != "" {
		page, code := requestAccessPage(t, s, period+"&object=panel")
		if code != 200 {
			t.Fatal(code)
		}
		data, err := json.Marshal(map[string]journalLogPage{"access": page, "all": all, "services": services})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("real HTTP attempts=1006 journal events=%d notices=%d; Access/General/Services PASS", len(access.Entries), notices)
}

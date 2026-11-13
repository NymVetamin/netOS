package api

import (
	"context"
	"database/sql"
	"github.com/netos-router/netos/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoginReadFailureReasonAndRetry(t *testing.T) {
	old := initialCredentialsPath
	initialCredentialsPath = filepath.Join(t.TempDir(), "absent")
	defer func() { initialCredentialsPath = old }()
	for _, tc := range []struct{ name, breakSQL, restoreSQL string }{
		{"user-read", "ALTER TABLE user_preferences RENAME TO hidden_preferences", "ALTER TABLE hidden_preferences RENAME TO user_preferences"},
		{"access-read", "UPDATE panel_access SET permissions='broken-json' WHERE username='admin'", "UPDATE panel_access SET permissions='{}' WHERE username='admin'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "read.db")
			st, err := store.Open(path)
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
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err = db.Exec(tc.breakSQL); err != nil {
				t.Fatal(err)
			}
			logger := &storageFallbackLogger{}
			s := &Server{Store: st, Logger: logger, loginFails: map[string]*failCounter{}, loginSlots: make(chan struct{}, maxConcurrentLogins), csrfTokens: map[string]string{}}
			request := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"test-password-123"}`))
				r.RemoteAddr = "192.0.2.1:1234"
				w := httptest.NewRecorder()
				s.handleLogin(w, r)
				return w
			}
			w := request()
			rows, err := st.ListAccessAudit(context.Background(), 100)
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != 401 || len(rows) != 1 || rows[0].Success || rows[0].Detail != loginCheckFailure {
				t.Fatal("incorrect failure reason", w.Code, rows)
			}
			t.Logf("read error: status=%d audit_detail=%s fail_count=%d", w.Code, rows[0].Detail, s.loginFails["192.0.2.1"].count)
			event, err := panelAccessEntry(rows[0])
			if err != nil || event.Severity != "warning" || event.Result != "failure" || !strings.Contains(event.Event, loginCheckFailure) {
				t.Fatal(event, err)
			}
			s.StorageRunner = &allPageRunner{}
			page, code := allPageRequest(t, s, filepath.Join(t.TempDir(), "dns.log"), "result=warning")
			if code != 200 || len(page.Entries) != 1 || page.Entries[0].Event != event.Event {
				t.Fatal("general SQL warning", code, page)
			}
			if _, err = db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'private-storage-detail'); END"); err != nil {
				t.Fatal(err)
			}
			w = request()
			if w.Code != 401 || len(logger.lines) != 1 {
				t.Fatal("fallback", w.Code, logger.lines)
			}
			fallback := logEntry{Unit: "netosd.service", Message: "[инфо] " + logger.lines[0]}
			if !panelJournalFields(&fallback) || fallback.Severity != "warning" || fallback.Result != "failure" || !strings.Contains(fallback.Event, loginCheckFailure) || strings.Contains(fallback.Message, "private-storage-detail") {
				t.Fatal(fallback)
			}
			if _, err = db.Exec("DROP TRIGGER fail_audit"); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(tc.restoreSQL); err != nil {
				t.Fatal(err)
			}
			w = request()
			rows, err = st.ListAccessAudit(context.Background(), 100)
			if err != nil || w.Code != 200 || len(rows) != 2 || !rows[0].Success {
				t.Fatal("retry", w.Code, rows, err)
			}
		})
	}
}

func TestLoginRejectionDoesNotInventStorageFailure(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	hash, err := HashPassword("disabled-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.SavePanelUser(store.PanelUser{Username: "disabled", Role: "viewer", PanelAccess: store.PanelAccess{Enabled: false}}, hash, true, false, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"username":"unknown","password":"initial-password-123"}`, `{"username":"admin","password":"wrong"}`, `{"username":"disabled","password":"disabled-password"}`} {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		s.handleLogin(w, r)
		rows, err := s.Store.ListAccessAudit(context.Background(), 100)
		if err != nil || w.Code != 401 || len(rows) == 0 || rows[0].Detail == loginCheckFailure {
			t.Fatal(w.Code, rows, err)
		}
		e, err := panelAccessEntry(rows[0])
		if err != nil || e.Severity != "" {
			t.Fatal(e, err)
		}
	}
}

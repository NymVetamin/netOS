package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/store"
)

type storageFallbackLogger struct{ lifecycleLogger }

func (l *storageFallbackLogger) Infof(format string, args ...any) {
	l.lifecycleLogger.Infof(format, args...)
	if os.Getenv("NETOS_STORAGE_JOURNAL_CHILD") == "1" {
		log.Printf("[инфо] "+format, args...)
	}
}

func BenchmarkLoginStorageFallback(b *testing.B) {
	for _, history := range []int{30, 10000} {
		for _, enabled := range []bool{false, true} {
			b.Run(fmt.Sprintf("history%d/journal%v", history, enabled), func(b *testing.B) {
				path := filepath.Join(b.TempDir(), "bench.db")
				st, err := store.Open(path)
				if err != nil {
					b.Fatal(err)
				}
				defer st.Close()
				hash, err := HashPassword("bench-password")
				if err != nil {
					b.Fatal(err)
				}
				if _, err = st.CreateUser("admin", hash, "admin"); err != nil {
					b.Fatal(err)
				}
				db, err := sql.Open("sqlite", path)
				if err != nil {
					b.Fatal(err)
				}
				defer db.Close()
				if _, err = db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?) INSERT INTO audit(at,user,action,target,detail,source_ip,success) SELECT 0,'admin','login','','','',1 FROM n`, history); err != nil {
					b.Fatal(err)
				}
				if _, err = db.Exec("CREATE TRIGGER fixture_fail BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
					b.Fatal(err)
				}
				logger := &earlyAuditBenchmarkLogger{writer: log.New(io.Discard, "", log.LstdFlags)}
				s := &Server{Store: st, loginFails: map[string]*failCounter{}, loginSlots: make(chan struct{}, maxConcurrentLogins), csrfTokens: map[string]string{}}
				if enabled {
					s.Logger = logger
				}
				old := initialCredentialsPath
				initialCredentialsPath = filepath.Join(b.TempDir(), "absent")
				defer func() { initialCredentialsPath = old }()
				b.ReportAllocs()
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					s.loginAudit = earlyLoginAudit{}
					logger.calls = 0
					r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"bench-password"}`))
					r.RemoteAddr = "192.0.2.1:1234"
					w := httptest.NewRecorder()
					s.handleLogin(w, r)
					want := 0
					if enabled {
						want = 1
					}
					if w.Code != 200 || len(w.Result().Cookies()) != 1 || logger.calls != want {
						b.Fatal(w.Code, logger.calls)
					}
				}
			})
		}
	}
}

func TestLoginStorageFailureFallbackAndRetry(t *testing.T) {
	old := initialCredentialsPath
	initialCredentialsPath = filepath.Join(t.TempDir(), "absent-credentials")
	defer func() { initialCredentialsPath = old }()
	for _, tc := range []struct {
		name, table, password string
		status, sessions      int
	}{
		{"session-write", "sessions", "initial-password-123", 500, 0},
		{"success-audit", "audit", "initial-password-123", 200, 1},
		{"failure-audit", "audit", "wrong-password", 401, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "research.db")
			st, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			hash, err := HashPassword("initial-password-123")
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
			if _, err = db.Exec("CREATE TRIGGER fixture_fail BEFORE INSERT ON " + tc.table + " BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
				t.Fatal(err)
			}
			logger := &storageFallbackLogger{}
			s := &Server{Store: st, Logger: logger, loginFails: map[string]*failCounter{}, loginSlots: make(chan struct{}, maxConcurrentLogins), csrfTokens: map[string]string{}}
			request := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"`+tc.password+`"}`))
				r.RemoteAddr = "192.0.2.1:12345"
				w := httptest.NewRecorder()
				s.handleLogin(w, r)
				return w
			}
			w := request()
			var sessions int
			if err = db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&sessions); err != nil {
				t.Fatal(err)
			}
			entries, err := st.ListAccessAudit(context.Background(), 100)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("status=%d sessions=%d SQL_events=%d logger_events=%d cookies=%d", w.Code, sessions, len(entries), len(logger.lines), len(w.Result().Cookies()))
			if w.Code != tc.status || sessions != tc.sessions || len(entries) != 0 || len(logger.lines) != 1 {
				t.Fatal("missing fallback or changed response")
			}
			row := map[string]json.RawMessage{}
			for k, v := range map[string]string{"_SYSTEMD_UNIT": "netosd.service", "MESSAGE": "[инфо] " + logger.lines[0]} {
				row[k], _ = json.Marshal(v)
			}
			access, ok := journalLogEntry(row, "access")
			all, allOK := allJournalEntry(row, false)
			want := "failure"
			if tc.status == 200 {
				want = "success"
			}
			if !ok || !allOK || access != all || access.Result != want || access.Severity != "warning" || access.User != "admin" || access.Address != "192.0.2.1" {
				t.Fatal(access, all)
			}
			if _, keep := journalLogEntry(row, "services"); keep {
				t.Fatal("service duplicate")
			}
			if strings.Contains(access.Message, tc.password) || strings.Contains(access.Message, "fixture") {
				t.Fatal("secret or raw storage error")
			}
			cookies := w.Result().Cookies()
			if tc.status == 200 {
				if len(cookies) != 1 {
					t.Fatal("cookie missing")
				}
				if user, err := st.SessionUser(cookies[0].Value); err != nil || user != "admin" {
					t.Fatal("session not usable", err)
				}
			} else if len(cookies) != 0 {
				t.Fatal("cookie on failure")
			}
			if _, err = db.Exec("DROP TRIGGER fixture_fail"); err != nil {
				t.Fatal(err)
			}
			w = request()
			entries, err = st.ListAccessAudit(context.Background(), 100)
			if err != nil {
				t.Fatal(err)
			}
			retryStatus := 200
			if tc.password == "wrong-password" {
				retryStatus = 401
			}
			if len(entries) != 1 || len(logger.lines) != 1 || w.Code != retryStatus {
				t.Fatal("retry audit or duplicate fallback", len(entries), len(logger.lines), w.Code)
			}
			t.Logf("retry_status=%d SQL_events=%d", w.Code, len(entries))
		})
	}
}

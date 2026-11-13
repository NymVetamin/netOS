package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
)

func TestLogoutAuditRoutesFailureRetryAndIsolation(t *testing.T) {
	for _, role := range []string{"admin", "viewer", "limited"} {
		t.Run(role, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "logout.db")
			st, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, err = st.CreateUser("alice", "unused-password-hash", role); err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{"secret-token", "other-token"} {
				if _, err = st.CreateSession(token, "alice", "192.0.2.1", time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			s := &Server{Store: st, csrfTokens: map[string]string{"secret-token": "secret-csrf", "other-token": "other-csrf"}}
			h := s.Routes()
			cookie := &http.Cookie{Name: sessionCookie, Value: "secret-token"}
			request := func(csrf string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "/api/logout", nil)
				r.AddCookie(cookie)
				r.Header.Set(csrfHeader, csrf)
				r.RemoteAddr = "192.0.2.2:54321"
				r.Header.Set("X-Forwarded-For", "198.51.100.4")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			if w := request("wrong"); w.Code != 403 {
				t.Fatal(w.Code, w.Body.String())
			}
			if rows, err := st.ListAccessAudit(context.Background(), 300); err != nil || len(rows) != 0 {
				t.Fatal("CSRF rejection recorded as logout", rows, err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err = db.Exec("CREATE TRIGGER fail_logout BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture failure'); END"); err != nil {
				t.Fatal(err)
			}
			w := request("secret-csrf")
			if w.Code != 500 || len(w.Result().Cookies()) != 0 || s.csrfTokens["secret-token"] != "secret-csrf" {
				t.Fatal("failed logout cleared client session", w.Code, w.Body.String())
			}
			if _, err = st.SessionUser(cookie.Value); err != nil {
				t.Fatal("failed logout revoked session", err)
			}
			if _, err = db.Exec("DROP TRIGGER fail_logout"); err != nil {
				t.Fatal(err)
			}
			w = request("secret-csrf")
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
				t.Fatal(cookies)
			}
			if _, exists := s.csrfTokens[cookie.Value]; exists {
				t.Fatal("CSRF remained")
			}
			if s.csrfTokens["other-token"] != "other-csrf" {
				t.Fatal("other CSRF changed")
			}
			if _, err := st.SessionUser("other-token"); err != nil {
				t.Fatal(err)
			}
			if w := request("secret-csrf"); w.Code != 401 {
				t.Fatal("revoked token accepted", w.Code)
			}
			entries, err := s.panelAccessEntries(context.Background())
			if err != nil || len(entries) != 1 {
				t.Fatal(entries, err)
			}
			e := entries[0]
			if e.Event != "Выход из панели" || e.User != "alice" || e.Address != "192.0.2.2" || e.Result != "success" {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(e)
			if strings.Contains(string(raw), "secret-") || strings.Contains(string(raw), "password") {
				t.Fatal("session secret in event")
			}
		})
	}
}

func BenchmarkLogoutAuditRoute(b *testing.B) {
	for _, n := range []int{30, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "logout.db")
			st, err := store.Open(path)
			if err != nil {
				b.Fatal(err)
			}
			defer st.Close()
			if _, err := st.CreateUser("alice", "unused", "admin"); err != nil {
				b.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?) INSERT INTO audit(at,user,action,success) SELECT i,'alice','login',1 FROM n`, n); err != nil {
				b.Fatal(err)
			}
			if n > 30 {
				if _, err := db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO sessions(token,username,created_at,expires_at) SELECT 'other-'||i,'alice',0,9999999999 FROM n`); err != nil {
					b.Fatal(err)
				}
			}
			s := &Server{Store: st, csrfTokens: map[string]string{}}
			h := s.Routes()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if _, err := db.Exec(`INSERT INTO sessions(token,username,created_at,expires_at) VALUES('bench','alice',0,9999999999)`); err != nil {
					b.Fatal(err)
				}
				s.csrfTokens["bench"] = "csrf"
				b.StartTimer()
				w := serveAuthed(h, "POST", "/api/logout", nil, &http.Cookie{Name: sessionCookie, Value: "bench"}, "csrf")
				if w.Code != 200 {
					b.Fatal(w.Body.String())
				}
				b.StopTimer()
				if _, err := db.Exec(`DELETE FROM audit WHERE id=(SELECT MAX(id) FROM audit)`); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
	}
}

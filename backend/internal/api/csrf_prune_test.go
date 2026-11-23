package api

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
)

func TestPruneRevokedPanelSessionCSRF(t *testing.T) {
	s, cookie, csrf, _ := transactionServer(t)
	s.Logger = &lifecycleLogger{}
	u := store.PanelUser{Username: "operator", Role: "limited", PanelAccess: store.PanelAccess{Enabled: true, Permissions: map[string]string{"system": "view"}}}
	if _, err := s.Store.SavePanelUser(u, "synthetic-hash", true, false, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		token := fmt.Sprintf("synthetic-session-%d", i)
		if _, err := s.Store.CreateSession(token, u.Username, "test", time.Hour); err != nil {
			t.Fatal(err)
		}
		s.csrfTokens[token] = "synthetic-csrf"
		if i%2 == 0 {
			u.Permissions["system"] = "manage"
		} else {
			u.Permissions["system"] = "view"
		}
		body, _ := json.Marshal(u)
		w := serveAuthed(s.Routes(), "PUT", "/api/panel-users", body, cookie, csrf)
		if w.Code != 200 {
			t.Fatalf("update: %d %s", w.Code, w.Body.String())
		}
		if _, err := s.Store.SessionUser(token); err == nil {
			t.Fatal("session not revoked")
		}
		for range 2 {
			s.pruneOnce()
		}
		if _, ok := s.csrfTokens[token]; ok {
			t.Errorf("revoked CSRF retained: cycle %d", i)
		}
		if s.csrfTokens[cookie.Value] != csrf {
			t.Fatal("live administrator CSRF removed")
		}
		if i == 0 {
			// A request authenticated before revocation can register CSRF late.
			s.csrfTokens[token] = "late"
			s.pruneOnce()
			if _, ok := s.csrfTokens[token]; ok {
				t.Error("late orphan survived the next cleanup")
			}
		}
	}
	if _, err := s.Store.CreateSession("unchanged", u.Username, "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	s.csrfTokens["unchanged"] = "keep"
	body, _ := json.Marshal(u)
	if w := serveAuthed(s.Routes(), "PUT", "/api/panel-users", body, cookie, csrf); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	s.pruneOnce()
	if s.csrfTokens["unchanged"] != "keep" {
		t.Fatal("unchanged access revoked CSRF")
	}
	if w := serveAuthed(s.Routes(), "DELETE", "/api/panel-users/"+u.Username, nil, cookie, csrf); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	s.pruneOnce()
	if _, ok := s.csrfTokens["unchanged"]; ok {
		t.Error("deleted user CSRF retained")
	}
	if err := s.Store.Close(); err != nil {
		t.Fatal(err)
	}
	s.pruneOnce()
	if s.csrfTokens[cookie.Value] != csrf {
		t.Fatal("database error removed live CSRF")
	}
}

func TestPruneCSRFConcurrentSessionRegistration(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	s.Logger = &lifecycleLogger{}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 10; i++ {
			token := fmt.Sprintf("concurrent-%d", i)
			if _, err := s.Store.CreateSession(token, "admin", "test", time.Hour); err != nil {
				done <- err
				return
			}
			s.csrfMu.Lock()
			s.csrfTokens[token] = "test"
			s.csrfMu.Unlock()
		}
		done <- nil
	}()
	for range 20 {
		s.pruneOnce()
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if s.csrfTokens[fmt.Sprintf("concurrent-%d", i)] != "test" {
			t.Fatalf("live session %d lost its CSRF", i)
		}
	}
}

func BenchmarkPruneOrphanCSRF(b *testing.B) {
	for _, n := range []int{16, 2048} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			st, err := store.Open(filepath.Join(b.TempDir(), "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer st.Close()
			s := &Server{Store: st, Logger: &lifecycleLogger{}}
			tokens := make([]string, n)
			for i := range tokens {
				tokens[i] = fmt.Sprintf("synthetic-%d", i)
				if i%2 == 0 {
					if _, err := st.CreateSession(tokens[i], fmt.Sprintf("user-%d", i), "test", time.Hour); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				s.csrfTokens = make(map[string]string, n)
				for _, token := range tokens {
					s.csrfTokens[token] = "test"
				}
				s.pruneOnce()
			}
		})
	}
}

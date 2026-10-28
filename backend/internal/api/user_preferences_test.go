package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestOwnHintsPreferenceAuthenticationAndIsolation(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	h := s.Routes()
	body := []byte(`{"show_hints":false}`)
	for _, tc := range []struct {
		cookie *http.Cookie
		token  string
		want   int
	}{
		{nil, "", 401}, {cookie, "wrong", 403}, {cookie, csrf, 200},
	} {
		if w := serveAuthed(h, "PUT", "/api/preferences", body, tc.cookie, tc.token); w.Code != tc.want {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	}
	for _, bad := range []string{`{}`, `{"show_hints":null}`, `{"show_hints":"false"}`, `{"show_hints":true,"username":"other"}`} {
		if w := serveAuthed(h, "PUT", "/api/preferences", []byte(bad), cookie, csrf); w.Code != 400 {
			t.Fatalf("accepted %s: %d", bad, w.Code)
		}
	}
	for _, role := range []string{"viewer", "limited"} {
		if _, err := s.Store.CreateUser(role, "hash", role); err != nil {
			t.Fatal(err)
		}
		token := role + "-session"
		if _, err := s.Store.CreateSession(token, role, "127.0.0.1", time.Hour); err != nil {
			t.Fatal(err)
		}
		s.csrfTokens[token] = "csrf"
		c := &http.Cookie{Name: sessionCookie, Value: token}
		if w := serveAuthed(h, "PUT", "/api/preferences", []byte(`{"show_hints":true}`), c, "csrf"); w.Code != 200 {
			t.Fatalf("%s: %d %s", role, w.Code, w.Body.String())
		}
	}
	w := serveAuthed(h, "GET", "/api/session", nil, cookie, "")
	var session struct {
		ShowHints *bool `json:"show_hints"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || session.ShowHints == nil || *session.ShowHints {
		t.Fatalf("session lost preference: %s", w.Body.String())
	}
	if s.draft != nil {
		t.Fatal("preference created configuration draft")
	}
}

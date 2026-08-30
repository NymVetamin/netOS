package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginFailuresExpire(t *testing.T) {
	s := &Server{loginFails: map[string]*failCounter{
		"old": {count: 9, until: time.Now().Add(time.Hour), last: time.Now().Add(-loginFailureTTL - time.Minute)},
	}}
	if _, blocked := s.loginBlocked("old"); blocked {
		t.Fatal("устаревшая блокировка продолжает действовать")
	}
	if len(s.loginFails) != 0 {
		t.Fatal("устаревшая запись не удалена")
	}
}

func TestLoginRejectsOversizedPasswordBeforeHashing(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	body := `{"username":"admin","password":"` + strings.Repeat("x", maxPasswordBytes+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestVerifyPasswordRejectsHostileParameters(t *testing.T) {
	encoded := "$argon2id$v=19$m=4294967295,t=2,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if VerifyPassword("password", encoded) {
		t.Fatal("hostile Argon2 parameters were accepted")
	}
}

func TestLoginFailureTableIsBounded(t *testing.T) {
	s := &Server{loginFails: map[string]*failCounter{}}
	for i := 0; i < maxLoginSources+100; i++ {
		s.recordLoginFailure(fmt.Sprintf("192.0.2.%d", i))
	}
	if len(s.loginFails) != maxLoginSources {
		t.Fatalf("таблица выросла до %d, предел %d", len(s.loginFails), maxLoginSources)
	}
}

func TestPruneLoginFailuresKeepsRecentEntries(t *testing.T) {
	now := time.Now()
	s := &Server{loginFails: map[string]*failCounter{
		"old":    {last: now.Add(-loginFailureTTL - time.Second)},
		"recent": {last: now.Add(-time.Minute)},
	}}
	s.pruneLoginFailures(now)
	if _, ok := s.loginFails["old"]; ok {
		t.Fatal("старая запись осталась")
	}
	if _, ok := s.loginFails["recent"]; !ok {
		t.Fatal("свежая запись удалена")
	}
}

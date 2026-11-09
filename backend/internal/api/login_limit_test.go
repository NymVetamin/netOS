package api

import (
	"fmt"
	"io"
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

// Медленно передаваемое тело не должно занимать место проверки пароля:
// иначе два соединения без учётных данных закрывают вход всем остальным.
func TestSlowLoginBodiesDoNotBlockOtherLogins(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	var stalled []*io.PipeWriter
	done := make(chan struct{}, maxConcurrentLogins)
	for i := 0; i < maxConcurrentLogins; i++ {
		body, writer := io.Pipe()
		stalled = append(stalled, writer)
		req := httptest.NewRequest(http.MethodPost, "/api/login", body)
		req.RemoteAddr = "203.0.113.66:40000"
		go func() {
			s.handleLogin(httptest.NewRecorder(), req)
			done <- struct{}{}
		}()
	}
	defer func() {
		for _, writer := range stalled {
			_ = writer.Close()
		}
		for range stalled {
			<-done
		}
	}()
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"initial-password-123"}`))
	req.RemoteAddr = "192.0.2.10:40000"
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("вход при двух медленных запросах: %d %s", w.Code, w.Body.String())
	}
}

// Проверку Argon2 по-прежнему выполняют не больше maxConcurrentLogins
// запросов одновременно.
func TestLoginStillLimitsConcurrentPasswordChecks(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	for i := 0; i < maxConcurrentLogins; i++ {
		s.loginSlots <- struct{}{}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"initial-password-123"}`))
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want %d", w.Code, http.StatusTooManyRequests)
	}
}

func TestLoginBodyIsBounded(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	// Самый длинный допустимый запрос: каждый байт логина и пароля
	// экранирован как \u00XX.
	longest := `{"username":"` + strings.Repeat(`\u0001`, 64) + `","password":"` + strings.Repeat(`\u0001`, maxPasswordBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(longest))
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("допустимый по размеру запрос: got %d, want %d", w.Code, http.StatusUnauthorized)
	}

	padded := `{"username":"admin","password":"x"` + strings.Repeat(" ", maxLoginBodyBytes) + `}`
	req = httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(padded))
	w = httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("тело больше предела: got %d, want %d", w.Code, http.StatusBadRequest)
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

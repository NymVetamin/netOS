package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
)

func TestGeneratePasswordBoundsAndAlphabet(t *testing.T) {
	for _, length := range []int{-1, 0, maxGeneratedPasswordLength + 1} {
		if _, err := GeneratePassword(length); err == nil {
			t.Errorf("GeneratePassword(%d) succeeded", length)
		}
	}
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	first, err := GeneratePassword(64)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GeneratePassword(64)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 || strings.Trim(first, alphabet) != "" {
		t.Fatalf("generated password has invalid length or characters: %q", first)
	}
	if first == second {
		t.Fatal("two generated passwords unexpectedly match")
	}
}

// newAuthedServer заводит сервер с одним администратором и живой сессией.
func newAuthedServer(t *testing.T) (*Server, *http.Cookie, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	hash, err := HashPassword("initial-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser("admin", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession("session-token", "admin", "127.0.0.1", time.Hour); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Store: st, csrfTokens: map[string]string{"session-token": "csrf-token"},
		loginFails: map[string]*failCounter{}, loginSlots: make(chan struct{}, maxConcurrentLogins),
	}
	return s, &http.Cookie{Name: sessionCookie, Value: "session-token"}, "csrf-token"
}

// Обязательной смены пароля нет: пароль первого запуска и так случайный.
// Раньше до его смены сервер отклонял любой изменяющий запрос, и панель
// молча не работала — вернуться к этому нельзя.
func TestFreshAdminMayChangeConfigRightAway(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)

	reached := false
	handler := s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPut, "/api/config", nil)
	req.AddCookie(cookie)
	req.Header.Set(csrfHeader, csrf)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK || !reached {
		t.Fatalf("изменяющий запрос отклонён: код %d, тело %s", w.Code, w.Body.String())
	}
}

// Пароль первого запуска лежит на диске открытым текстом. Уборку раньше делала
// обязательная смена пароля; без неё файл жил бы вечно, поэтому его удаляет
// первый успешный вход.
func TestLoginRemovesInitialCredentials(t *testing.T) {
	s, _, _ := newAuthedServer(t)

	credentials := filepath.Join(t.TempDir(), "initial-credentials")
	if err := os.WriteFile(credentials, []byte("Пароль: initial-password-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := initialCredentialsPath
	initialCredentialsPath = credentials
	t.Cleanup(func() { initialCredentialsPath = old })

	body := `{"username":"admin","password":"initial-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("вход не удался: код %d, тело %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(credentials); err == nil {
		t.Fatal("пароль остался лежать на диске открытым текстом после входа")
	}
}

// Ответы сервера не должны обещать панели поле, которого больше нет.
func TestLoginResponseHasNoMustChange(t *testing.T) {
	s, _, _ := newAuthedServer(t)

	body := `{"username":"admin","password":"initial-password-123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleLogin(w, req)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["must_change"]; ok {
		t.Fatalf("сервер всё ещё отдаёт must_change: %v", got)
	}
}

func TestPasswordChangeRevokesAllUserSessions(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	if _, err := s.Store.CreateSession("other-session", "admin", "192.0.2.1", time.Hour); err != nil {
		t.Fatal(err)
	}
	s.csrfTokens["other-session"] = "other-csrf"

	body := `{"current":"initial-password-123","new":"new-password-456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/password", strings.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set(csrfHeader, csrf)
	w := httptest.NewRecorder()
	s.requireAuth(s.handleChangePassword).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("password change failed: %d %s", w.Code, w.Body.String())
	}
	for _, token := range []string{"session-token", "other-session"} {
		if _, err := s.Store.SessionUser(token); err == nil {
			t.Fatalf("session %q remained valid", token)
		}
		if _, ok := s.csrfTokens[token]; ok {
			t.Fatalf("CSRF state for %q remained in memory", token)
		}
	}
	setCookies := w.Result().Cookies()
	if len(setCookies) == 0 || setCookies[0].Name != sessionCookie || setCookies[0].MaxAge >= 0 {
		t.Fatalf("session cookie was not expired: %#v", setCookies)
	}
}

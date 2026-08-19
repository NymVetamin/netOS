package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func TestSaveConfigRejectsStaleDraft(t *testing.T) {
	s := &Server{draftVersion: 7, Engine: apply.NewEngine(nil, true)}
	body, _ := json.Marshal(config.Default())
	req := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	req.Header.Set("If-Match", "6")
	w := httptest.NewRecorder()
	s.handleSaveConfig(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}

func TestSaveConfigRequiresDraftPrecondition(t *testing.T) {
	s := &Server{draftVersion: 1, Engine: apply.NewEngine(nil, true)}
	body, _ := json.Marshal(config.Default())
	w := httptest.NewRecorder()
	s.handleSaveConfig(w, httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body)))
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428", w.Code)
	}
}

func TestApplyRejectsMalformedJSON(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.handleApply(w, httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewBufferString(`{"comment":`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestSessionReissuesCSRFTokenAfterReload(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateUser("admin", "unused", "admin"); err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, csrfTokens: map[string]string{}}
	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxUser, "admin"))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "existing-session"})
	w := httptest.NewRecorder()
	s.handleSession(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["csrf_token"] == "" {
		t.Fatal("сервер не восстановил CSRF-токен")
	}
}

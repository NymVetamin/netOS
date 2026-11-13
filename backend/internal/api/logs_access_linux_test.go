//go:build linux

package api

import (
	"context"
	"encoding/json"
	"github.com/netos-router/netos/internal/system"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegrationAccessLogs(t *testing.T) {
	if os.Getenv("NETOS_LOGS_INTEGRATION") != "1" {
		t.Skip("requires authorized test machine and SSH fixtures")
	}
	s, _, _ := newAuthedServer(t)
	s.StorageRunner = &system.Exec{Timeout: 10 * time.Second}
	for _, password := range []string{"initial-password-123", "wrong-log-test"} {
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
		req.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		s.handleLogin(w, req)
		expected := 200
		if password == "wrong-log-test" {
			expected = 401
		}
		if w.Code != expected {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	req := httptest.NewRequest("GET", "/api/logs?kind=access", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxRole, "admin"))
	w := httptest.NewRecorder()
	s.handleLogs(w, req)
	var data struct {
		Entries  []logEntry
		Warnings []string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || w.Code != 200 || len(data.Warnings) > 0 {
		t.Fatal(err, w.Code, data.Warnings)
	}
	found := map[string]bool{}
	for _, e := range data.Entries {
		if e.Protocol == "panel" && e.User == "admin" {
			found["panel-"+e.Result] = true
		}
		if e.Protocol == "ssh" && e.User == "root" && e.Result == "success" {
			found["ssh-success"] = true
		}
		if e.Protocol == "ssh" && e.User == "netos-log-invalid" && e.Result == "failure" {
			found["ssh-failure"] = true
		}
	}
	for _, key := range []string{"panel-success", "panel-failure", "ssh-success", "ssh-failure"} {
		if !found[key] {
			t.Error("missing event", key)
		}
	}
}

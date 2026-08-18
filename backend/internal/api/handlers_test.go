package api

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func viewerRequest(method, path string) *http.Request {
	return &http.Request{Method: method, URL: &url.URL{Path: path}}
}

func TestViewerConfigIsRedacted(t *testing.T) {
	cfg := config.Default()
	cfg.WANs = []config.WAN{{Password: "wan-secret"}}
	cfg.WiFi = []config.WiFiRadio{{SSIDs: []config.WiFiSSID{{Password: "wifi-secret"}}}}

	redacted := redactConfig(cfg)
	if redacted == nil {
		t.Fatal("не удалось скопировать конфигурацию")
	}
	if redacted.WANs[0].Password != "" || redacted.WiFi[0].SSIDs[0].Password != "" {
		t.Fatal("viewer получил пароль из конфигурации")
	}
	if cfg.WANs[0].Password != "wan-secret" || cfg.WiFi[0].SSIDs[0].Password != "wifi-secret" {
		t.Fatal("редактирование изменило исходную конфигурацию")
	}
}

func TestViewerPermissions(t *testing.T) {
	allowed := []*http.Request{
		viewerRequest(http.MethodGet, "/api/status"),
		viewerRequest(http.MethodGet, "/api/routes"),
		viewerRequest(http.MethodGet, "/api/config"),
		viewerRequest(http.MethodPost, "/api/logout"),
		viewerRequest(http.MethodPost, "/api/password"),
	}
	for _, r := range allowed {
		if !viewerAllowed(r) {
			t.Errorf("viewer неожиданно запрещён %s %s", r.Method, r.URL.Path)
		}
	}

	denied := []*http.Request{
		viewerRequest(http.MethodGet, "/api/revisions/1"),
		viewerRequest(http.MethodPut, "/api/config"),
		viewerRequest(http.MethodPost, "/api/config/apply"),
	}
	for _, r := range denied {
		if viewerAllowed(r) {
			t.Errorf("viewer неожиданно разрешён %s %s", r.Method, r.URL.Path)
		}
	}
}

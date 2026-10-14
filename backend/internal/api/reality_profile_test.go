package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestRealityProfileAfterRedactedEdit(t *testing.T) {
	private := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{ID: "s", Type: "xray", Config: map[string]any{"protocol": "reality", "private_key": private, "public_endpoint": "[2001:db8::1]:443", "server_names": []string{"example.com"}, "short_ids": []string{"abcd"}, "flow": "xtls-rprx-vision"}, Peers: []config.VPNPeer{{ID: "p", Name: "Телефон #1", Credentials: map[string]string{"uuid": "12345678-1234-1234-1234-123456789abc"}}}}}
	visible, err := redactAdminConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !visible.VPNServers[0].RealityKeySet || visible.VPNServers[0].Config["private_key"] != "" || visible.VPNServers[0].Peers[0].Credentials["uuid"] != "" {
		t.Fatal("invalid secret metadata/redaction")
	}
	mergeRedactedSecrets(visible, cfg)
	if visible.VPNServers[0].RealityKeySet {
		t.Fatal("response metadata persisted")
	}
	// Round trip as a reloaded saved draft, without browser-held secrets.
	data, _ := json.Marshal(visible)
	var reload config.Config
	json.Unmarshal(data, &reload)
	s := &Server{draft: &reload}
	request := func(role, id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/reality-profile", nil)
		r.SetPathValue("id", "s")
		r.SetPathValue("peer", id)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, role))
		w := httptest.NewRecorder()
		s.handleRealityClientProfile(w, r)
		return w
	}
	for _, sid := range []string{"abcd", "1234567890abcdef"} {
		reload.VPNServers[0].Config["short_ids"] = []string{sid}
		for i := 0; i < 2; i++ {
			w := request("admin", "p")
			var result map[string]string
			json.Unmarshal(w.Body.Bytes(), &result)
			u, err := url.Parse(result["link"])
			if err != nil {
				t.Fatal(err)
			}
			public, _ := xrayPublicKey(private)
			if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), private) || u.User.Username() != cfg.VPNServers[0].Peers[0].Credentials["uuid"] || u.Query().Get("pbk") != public || u.Query().Get("sid") != sid || u.Host != "[2001:db8::1]:443" || u.Fragment != "Телефон #1" {
				t.Fatalf("invalid profile: status %d", w.Code)
			}
		}
	}
	if request("viewer", "p").Code != 403 || request("admin", "missing").Code != 404 {
		t.Fatal("authorization/lookup failed")
	}
	reload.VPNServers[0].Config["public_endpoint"] = ""
	if request("admin", "p").Code != 409 {
		t.Fatal("missing endpoint exported")
	}
	reload.VPNServers[0].Config["public_endpoint"] = "example.com:443"
	reload.VPNServers[0].Config["private_key"] = ""
	if request("admin", "p").Code != 409 {
		t.Fatal("missing key exported")
	}
}

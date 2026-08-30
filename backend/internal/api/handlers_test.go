package api

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestGenerateWireGuardKeypair(t *testing.T) {
	privateKey, publicKey, err := generateWireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"private": privateKey, "public": publicKey} {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s key is invalid: %q (%v)", name, value, err)
		}
	}
	if privateKey == publicKey {
		t.Fatal("private and public keys are identical")
	}
	derived, err := wireGuardPublicKey(privateKey)
	if err != nil || derived != publicKey {
		t.Fatalf("public key derivation mismatch: %q, %v", derived, err)
	}
}

func TestGenerateXrayKeypair(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	derived, err := xrayPublicKey(privateKey)
	if err != nil || derived != publicKey {
		t.Fatalf("public key derivation mismatch: %q, %v", derived, err)
	}
	for name, value := range map[string]string{"private": privateKey, "public": derived} {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s key is invalid: %q (%v)", name, value, err)
		}
	}
}

func viewerRequest(method, path string) *http.Request {
	return &http.Request{Method: method, URL: &url.URL{Path: path}}
}

func TestViewerConfigIsRedacted(t *testing.T) {
	cfg := config.Default()
	cfg.WANs = []config.WAN{{Password: "wan-secret"}}
	cfg.WiFi = []config.WiFiRadio{{SSIDs: []config.WiFiSSID{{Password: "wifi-secret"}}}}
	cfg.Channels = append(cfg.Channels, config.Channel{Config: map[string]any{
		"private_key": "channel-private", "endpoint": "vpn.example:51820",
		"transport": map[string]any{"auth_token": "nested-token"},
	}})
	cfg.VPNServers = []config.VPNServer{{
		Config: map[string]any{"private-key": "server-private", "listen": "0.0.0.0"},
		Peers:  []config.VPNPeer{{Credentials: map[string]string{"private_key": "peer-private", "public_key": "peer-public"}}},
	}}

	redacted, err := redactConfig(cfg)
	if err != nil {
		t.Fatalf("не удалось скопировать конфигурацию: %v", err)
	}
	if redacted.WANs[0].Password != "" || redacted.WiFi[0].SSIDs[0].Password != "" {
		t.Fatal("viewer получил пароль из конфигурации")
	}
	if redacted.Channels[1].Config["private_key"] != "" ||
		redacted.Channels[1].Config["transport"].(map[string]any)["auth_token"] != "" ||
		redacted.VPNServers[0].Config["private-key"] != "" {
		t.Fatal("viewer получил секрет из конфигурации VPN")
	}
	if redacted.VPNServers[0].Peers[0].Credentials["public_key"] != "" {
		t.Fatal("viewer получил учётные данные VPN-клиента")
	}
	if redacted.Channels[1].Config["endpoint"] == "" || redacted.VPNServers[0].Config["listen"] == "" {
		t.Fatal("редактирование скрыло несекретные параметры")
	}
	if cfg.WANs[0].Password != "wan-secret" || cfg.WiFi[0].SSIDs[0].Password != "wifi-secret" {
		t.Fatal("редактирование изменило исходную конфигурацию")
	}
	if cfg.Channels[1].Config["private_key"] != "channel-private" ||
		cfg.VPNServers[0].Peers[0].Credentials["private_key"] != "peer-private" {
		t.Fatal("редактирование изменило исходные секреты VPN")
	}
}

func TestViewerPermissions(t *testing.T) {
	allowed := []*http.Request{
		viewerRequest(http.MethodGet, "/api/status"),
		viewerRequest(http.MethodGet, "/api/routes"),
		viewerRequest(http.MethodGet, "/api/config"),
		viewerRequest(http.MethodGet, "/api/vpn-servers/home/certificate"),
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

// Диагностика в панели показывает конфиги демонов, которые работают. Список
// приходит отсюда: пока он был зашит в панели, она показывала dnsmasq и на
// машине, где выбраны unbound и ISC DHCP, а их собственные конфиги скрывала.
func TestRenderListFollowsChosenDaemons(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "isc-dhcp-server"
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "unbound", 53

	s := &Server{draft: cfg}
	w := httptest.NewRecorder()
	s.handleRenderList(w, httptest.NewRequest(http.MethodGet, "/api/render", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var got struct {
		Artifacts []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, a := range got.Artifacts {
		if a.Title == "" {
			t.Errorf("артефакт %q без названия для вкладки", a.ID)
		}
		seen[a.ID] = true
	}
	for _, want := range []string{"iptables", "isc-dhcp", "unbound", "resolv"} {
		if !seen[want] {
			t.Errorf("в диагностике нет %q: %v", want, got.Artifacts)
		}
	}
	if seen["dnsmasq"] {
		t.Errorf("показан выключенный dnsmasq: %v", got.Artifacts)
	}
}

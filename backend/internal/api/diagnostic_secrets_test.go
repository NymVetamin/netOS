package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/render"
)

func TestDiagnosticArtifactsHideSecretsWithoutChangingConfiguration(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "office", Interface: "lan", RouterAddress: "192.168.50.1/24", Enabled: true}}
	cfg.WANs = []config.WAN{{Password: "wan-secret"}}
	cfg.DDNS.Token, cfg.DDNS.Password = "ddns-token", "ddns-secret"
	cfg.WiFi = []config.WiFiRadio{{ID: "radio", Device: "wlan0", Enabled: true, Band: "2.4", Channel: 6, Width: 20, Country: "FI", SSIDs: []config.WiFiSSID{{ID: "ssid", SSID: "Office", Network: "office", Enabled: true, Security: "wpa2", Password: "wifi-secret"}}}}
	cfg.Channels = append(cfg.Channels,
		config.Channel{ID: "wg", Name: "WG", Index: 1, Type: "wireguard", Enabled: true, Config: map[string]any{"private_key": "wg-private", "preshared_key": "wg-psk", "peer_public_key": "peer-public", "endpoint": "vpn.example:51820", "allowed_ips": []string{"0.0.0.0/0"}}},
		config.Channel{ID: "xr", Name: "XR", Index: 2, Type: "xray", Enabled: true, Config: map[string]any{"outbound": map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "vpn.example", "users": []any{map[string]any{"id": "xray-uuid"}}}}}, "streamSettings": map[string]any{"realitySettings": map[string]any{"privateKey": "reality-private", "shortIds": []string{"short-secret"}}, "wsSettings": map[string]any{"headers": map[string]any{"Authorization": "Bearer header-secret"}}}}}},
		config.Channel{ID: "oc", Type: "openconnect", Config: map[string]any{"password": "oc-secret"}},
	)
	cfg.VPNServers = []config.VPNServer{
		{ID: "wg-server", Index: 1, Name: "WG server", Type: "wireguard", Enabled: true, Port: 51821, Subnet: "10.10.0.1/24", Config: map[string]any{"private_key": "server-private"}, Peers: []config.VPNPeer{{ID: "peer", Enabled: true, Address: "10.10.0.2", Credentials: map[string]string{"public_key": "client-public", "preshared_key": "server-psk"}}}},
		{ID: "xr-server", Index: 2, Name: "XR server", Type: "xray", Enabled: true, Port: 443, Subnet: "10.20.0.1/24", Config: map[string]any{"private_key": "server-reality-private", "destination": "www.example.com:443", "server_names": []string{"www.example.com"}, "short_ids": []string{"server-short-secret"}}, Peers: []config.VPNPeer{{ID: "peer", Enabled: true, Address: "10.20.0.2", Credentials: map[string]string{"uuid": "server-uuid"}}}},
		{ID: "ike", Index: 3, Name: "IKE", Type: "ikev2", Enabled: true, Port: 500, Subnet: "10.30.0.1/24", Config: map[string]any{"server_identity": "vpn.example"}, Peers: []config.VPNPeer{{ID: "alice", Enabled: true, Address: "10.30.0.2", Credentials: map[string]string{"username": "alice", "password": "ike-secret"}}}},
	}
	secrets := []string{"wan-secret", "ddns-token", "ddns-secret", "wifi-secret", "wg-private", "wg-psk", "xray-uuid", "reality-private", "short-secret", "header-secret", "oc-secret", "server-private", "server-psk", "server-reality-private", "server-short-secret", "server-uuid", "ike-secret", base64.StdEncoding.EncodeToString([]byte("ike-secret"))}
	before, _ := json.Marshal(cfg)
	s := &Server{draft: cfg}
	for _, artifact := range render.All() {
		t.Run(artifact.ID, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/render/"+artifact.ID, nil)
			r.SetPathValue("kind", artifact.ID)
			s.handleRender(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d", w.Code)
			}
			for _, secret := range secrets {
				if strings.Contains(w.Body.String(), secret) {
					t.Error("diagnostic response exposes a fixture secret")
				}
			}
			if artifact.ID == "wireguard" && (!strings.Contains(w.Body.String(), "peer-public") || !strings.Contains(w.Body.String(), "vpn.example:51820")) {
				t.Error("public diagnostic details were lost")
			}
		})
	}
	after, _ := json.Marshal(cfg)
	if string(before) != string(after) {
		t.Fatal("diagnostics mutated the draft")
	}
	raw, err := render.Render("wireguard", cfg)
	if err != nil || !strings.Contains(raw, "wg-private") {
		t.Fatal("native/CLI rendering lost the operational key")
	}
}

func TestDiagnosticXrayTransportCredentials(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "socks", Index: 1, Type: "xray", Enabled: true,
		Config: map[string]any{"outbound": map[string]any{
			"protocol": "socks", "settings": map[string]any{"address": "proxy.example", "port": 1080, "user": "alice", "pass": "socks-credential"},
			"streamSettings": map[string]any{
				"tlsSettings":     map[string]any{"certificates": []any{map[string]any{"key": []string{"inline-key-material"}}}, "echServerKeys": "ech-key-material"},
				"realitySettings": map[string]any{"mldsa65Seed": "signing-seed-material", "publicKey": "public-key-material"},
			},
		}}})
	s := &Server{draft: cfg}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/render/xray", nil)
	r.SetPathValue("kind", "xray")
	s.handleRender(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	for _, secret := range []string{"socks-credential", "inline-key-material", "ech-key-material", "signing-seed-material"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Error("Xray diagnostic output exposes a credential")
		}
	}
	for _, public := range []string{"proxy.example", "alice", "public-key-material", "[REDACTED]"} {
		if !strings.Contains(w.Body.String(), public) {
			t.Errorf("diagnostic output lost %q", public)
		}
	}
}

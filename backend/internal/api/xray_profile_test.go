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

func profileTestServer(protocol string) config.VPNServer {
	return config.VPNServer{ID: "s", Index: 997, Name: "Profile test", Type: "xray", Port: 443, Enabled: true, DefaultChannel: "direct", Subnet: "10.98.0.1/24", Config: map[string]any{"protocol": protocol, "public_endpoint": "vpn.example.test:443", "method": "aes-256-gcm", "private_key": base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32))), "server_names": []string{"example.com"}, "short_ids": []string{"abcd"}, "flow": "xtls-rprx-vision"}, Peers: []config.VPNPeer{{ID: "p", Name: "Телефон #1", Enabled: true, Address: "10.98.0.2", Credentials: map[string]string{"uuid": "12345678-1234-1234-1234-123456789abc", "password": "test :+/@?& password", "username": "test:@user"}}}}
}

func TestXrayProfilesAllProtocols(t *testing.T) {
	for _, protocol := range []string{"reality", "vless", "vmess", "trojan", "hysteria", "shadowsocks", "socks", "http"} {
		t.Run(protocol, func(t *testing.T) {
			s := profileTestServer(protocol)
			if protocol == "http" {
				if _, err := xrayClientProfile(s, s.Peers[0], ""); err == nil {
					t.Fatal("HTTP Basic username with colon accepted")
				}
				s.Peers[0].Credentials["username"] = "test-user"
			}
			p, err := xrayClientProfile(s, s.Peers[0], "aabbcc")
			if err != nil {
				t.Fatal(err)
			}
			if p.Link == "" || p.Config == nil {
				t.Fatal("missing export")
			}
			inbound := p.Config["inbounds"].([]any)[0].(map[string]any)
			if inbound["settings"].(map[string]any)["udp"] != (protocol == "reality") {
				t.Fatal("changed existing client UDP behavior")
			}
			u, err := url.Parse(p.Link)
			if err != nil {
				t.Fatal(err)
			}
			if protocol == "vmess" {
				body, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(p.Link, "vmess://"))
				var vm map[string]string
				if err != nil || json.Unmarshal(body, &vm) != nil || vm["ps"] != s.Peers[0].Name || vm["id"] != s.Peers[0].Credentials["uuid"] || vm["port"] != "443" {
					t.Fatal("invalid VMess URI")
				}
			} else if u.Host != "vpn.example.test:443" || u.Fragment != s.Peers[0].Name {
				t.Fatal("endpoint or name lost")
			}
			if protocol == "hysteria" && (u.Query().Get("pinSHA256") != "aabbcc" || u.Query().Get("insecure") != "1" || u.User.Username() != s.Peers[0].Credentials["password"]) {
				t.Fatal("Hysteria TLS/auth lost")
			}
			if (protocol == "vless" || protocol == "trojan") && u.Query().Get("pcs") != "aabbcc" {
				t.Fatal("TLS pin lost")
			}
			if protocol == "socks" || protocol == "http" {
				password, _ := u.User.Password()
				if password != s.Peers[0].Credentials["password"] || u.User.Username() != s.Peers[0].Credentials["username"] {
					t.Fatal("proxy credentials changed")
				}
			}
			s.Peers[0].Credentials = nil
			if _, err := xrayClientProfile(s, s.Peers[0], ""); err == nil {
				t.Fatal("empty secrets exported")
			}
		})
	}
}

func TestXrayProfileEndpointAndPublicCARenewal(t *testing.T) {
	cfg := config.Default()
	s := profileTestServer("hysteria")
	s.Config["tls"] = map[string]any{"mode": "acme"}
	pin, err := xrayProfilePin(cfg, s)
	if err != nil || pin != "" {
		t.Fatal("ACME export requires or pins a leaf")
	}
	p, err := xrayClientProfile(s, s.Peers[0], pin)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Link, "insecure") || strings.Contains(p.Link, "pinSHA256") {
		t.Fatal("public certificate verification bypassed")
	}
	s.Config["tls"] = map[string]any{"mode": "panel"}
	cfg.System.Panel.TLS.Mode = "acme"
	if pin, err := xrayProfilePin(cfg, s); err != nil || pin != "" {
		t.Fatal("shared ACME certificate pinned")
	}
	for _, endpoint := range []string{"", "host", "host:0", "host:65536", "bad/host:443"} {
		s.Config["public_endpoint"] = endpoint
		if _, err := xrayClientProfile(s, s.Peers[0], ""); err == nil {
			t.Fatalf("invalid endpoint %q", endpoint)
		}
	}
}

func TestXrayProfileAfterReloadAndAuthorization(t *testing.T) {
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{profileTestServer("hysteria")}
	cfg.VPNServers[0].Config["tls"] = map[string]any{"mode": "acme"}
	visible, _ := redactAdminConfig(cfg)
	mergeRedactedSecrets(visible, cfg)
	s := &Server{draft: visible}
	request := func(role, peer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/xray-profile", nil)
		r.SetPathValue("id", "s")
		r.SetPathValue("peer", peer)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, role))
		w := httptest.NewRecorder()
		s.handleXrayClientProfile(w, r)
		return w
	}
	for i := 0; i < 2; i++ {
		w := request("admin", "p")
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("profile unavailable: %d", w.Code)
		}
		var profile xrayProfile
		if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(profile.Link)
		if u.User.Username() != cfg.VPNServers[0].Peers[0].Credentials["password"] {
			t.Fatal("stored secret lost")
		}
	}
	if request("viewer", "p").Code != 403 || request("admin", "missing").Code != 404 {
		t.Fatal("authorization/lookup")
	}
}

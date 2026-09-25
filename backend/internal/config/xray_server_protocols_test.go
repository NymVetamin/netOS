package config

import (
	"strings"
	"testing"
)

func TestXrayServerProtocolCredentialsAndPrivateProxyBind(t *testing.T) {
	base := func(protocol string) *Config {
		cfg := Default()
		cfg.Components = append(cfg.Components, Component{ID: "xray", Installed: true})
		server := VPNServer{
			ID: "xray", Index: 1, Name: "Xray", Type: "xray", Enabled: true,
			Subnet: "10.99.0.1/24", Port: 18081, DefaultChannel: "direct",
			Config: map[string]any{"protocol": protocol, "listen": "10.0.0.1", "method": "aes-256-gcm"},
			Peers:  []VPNPeer{{ID: "alice", Name: "Alice", Enabled: true, Address: "10.99.0.2", Credentials: map[string]string{}}},
		}
		cfg.VPNServers = []VPNServer{server}
		return cfg
	}
	for _, protocol := range []string{"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria"} {
		t.Run(protocol, func(t *testing.T) {
			cfg := base(protocol)
			creds := cfg.VPNServers[0].Peers[0].Credentials
			switch protocol {
			case "vless", "vmess":
				creds["uuid"] = "123e4567-e89b-12d3-a456-426614174000"
			case "trojan", "shadowsocks", "hysteria":
				creds["password"] = "0123456789abcdef"
			case "wireguard":
				cfg.VPNServers[0].Config["wg_private_key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
				creds["public_key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			default:
				creds["username"] = "alice"
				creds["password"] = "long-password"
			}
			if result := cfg.Validate(); result.HasErrors() {
				t.Fatalf("valid %s server rejected: %+v", protocol, result.Problems)
			}
			if protocol == "socks" || protocol == "http" {
				cfg.VPNServers[0].Config["listen"] = "0.0.0.0"
				if result := cfg.Validate(); !result.HasErrors() || !strings.Contains(result.Problems[0].Path, "listen") {
					t.Fatalf("public proxy bind accepted: %+v", result.Problems)
				}
			} else {
				field := map[string]string{"vless": "uuid", "vmess": "uuid", "trojan": "password", "shadowsocks": "password", "wireguard": "public_key", "hysteria": "password"}[protocol]
				delete(creds, field)
				if result := cfg.Validate(); !result.HasErrors() {
					t.Fatal("server without credentials accepted")
				}
			}
		})
	}
}

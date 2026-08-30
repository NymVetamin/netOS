package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validWGServerConfig() *Config {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := Default()
	cfg.Components = []Component{{ID: "wireguard", Installed: true}}
	cfg.VPNServers = []VPNServer{{
		ID: "srv", Index: 1, Name: "VPN", Enabled: true, Type: "wireguard", Subnet: "10.9.0.1/24", Port: 51820,
		Config: map[string]any{"private_key": key, "client_allowed_ips": []string{"0.0.0.0/0"}},
		Peers:  []VPNPeer{{ID: "phone", Name: "Phone", Enabled: true, Address: "10.9.0.2", Credentials: map[string]string{"public_key": key}}},
	}}
	return cfg
}

func TestWireGuardServerValidation(t *testing.T) {
	cfg := validWGServerConfig()
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("валидный сервер отклонён: %+v", result.Problems)
	}
	cfg.VPNServers[0].Peers[0].Address = "10.10.0.2"
	result := cfg.Validate()
	for _, problem := range result.Problems {
		if strings.Contains(problem.Path, "peers[0].address") {
			return
		}
	}
	t.Fatalf("адрес вне подсети принят: %+v", result.Problems)
}

func TestWireGuardServerRequiresComponent(t *testing.T) {
	cfg := validWGServerConfig()
	cfg.Components = nil
	for _, problem := range cfg.Validate().Problems {
		if problem.Path == "vpn_servers[0].enabled" {
			return
		}
	}
	t.Fatal("сервер без компонента WireGuard принят")
}

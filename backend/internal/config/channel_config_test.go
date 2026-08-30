package config

import (
	"encoding/base64"
	"testing"
)

func validWireGuardChannel() Channel {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return Channel{
		ID: "wg-home", Index: 1, Name: "Домой", Enabled: true,
		Type: "wireguard", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"address": "10.44.0.2/32", "private_key": key,
			"peer_public_key": key, "endpoint": "vpn.example:51820",
			"allowed_ips": []string{"0.0.0.0/0"}, "persistent_keepalive": 25,
		},
	}
}

func TestWireGuardChannelValidation(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "wireguard", Installed: true}}
	cfg.Channels = append(cfg.Channels, validWireGuardChannel())
	for _, problem := range cfg.Validate().Problems {
		if problem.Severity == "error" {
			t.Fatalf("валидный канал отклонён: %+v", problem)
		}
	}
}

func TestWireGuardChannelRejectsUnknownAndBrokenValues(t *testing.T) {
	cfg := Default()
	ch := validWireGuardChannel()
	ch.Config["private_key"] = "broken"
	ch.Config["endpoint"] = "without-port"
	ch.Config["allowed_ips"] = []string{"not-a-network"}
	ch.Config["surprise"] = true
	cfg.Channels = append(cfg.Channels, ch)
	if !cfg.Validate().HasErrors() {
		t.Fatal("сломанная конфигурация WireGuard принята")
	}
}

func TestPolicyMayUseEnabledWireGuardChannel(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "wireguard", Installed: true}}
	cfg.Channels = append(cfg.Channels, validWireGuardChannel())
	cfg.Policies = []Policy{{
		ID: "web-vpn", Name: "Web через VPN", Enabled: true, Priority: 100,
		Channel: "wg-home", Protocol: "tcp", DstPort: "443",
	}}
	for _, problem := range cfg.Validate().Problems {
		if problem.Severity == "error" {
			t.Fatalf("валидная политика отклонена: %+v", problem)
		}
	}
}

func TestPolicyRejectsUnsupportedSelectorAndDisabledChannel(t *testing.T) {
	cfg := Default()
	ch := validWireGuardChannel()
	ch.Enabled = false
	cfg.Channels = append(cfg.Channels, ch)
	cfg.Policies = []Policy{{
		ID: "domain-vpn", Enabled: true, Channel: "wg-home", Domains: []string{"example.com"},
	}}
	if !cfg.Validate().HasErrors() {
		t.Fatal("политика с неподдерживаемым селектором и выключенным каналом принята")
	}
}

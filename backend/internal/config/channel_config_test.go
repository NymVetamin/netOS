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

func TestWireGuardFailModesAndProbeValidation(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "wireguard", Installed: true}}
	ch := validWireGuardChannel()
	ch.FailMode = "fallback"
	ch.Fallback = "direct"
	ch.Probe = Probe{Enabled: true, Type: "tcp", Targets: []string{"1.1.1.1:443"}, Interval: 5, Timeout: 2, FailThreshold: 2, RiseThreshold: 1}
	cfg.Channels = append(cfg.Channels, ch)
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" {
			t.Fatalf("valid fallback rejected: %+v", p)
		}
	}

	cfg.Channels[0].Enabled = false
	if !problem(t, cfg, "channels", "выключенный запасной") {
		t.Fatal("disabled fallback channel accepted")
	}
}

func TestOpenConnectChannelValidation(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "openconnect", Installed: true}}
	cfg.Channels = append(cfg.Channels, Channel{
		ID: "office", Index: 2, Name: "Office", Enabled: true,
		Type: "openconnect", Mode: "tun", FailMode: "block",
		Config: map[string]any{"server": "https://vpn.example.com", "username": "alice", "password": "secret", "protocol": "anyconnect"},
	})
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" {
			t.Fatalf("valid OpenConnect channel rejected: %+v", p)
		}
	}
	cfg.Channels[1].Config["server"] = "not-a-url"
	if !problem(t, cfg, "config.server", "https://") {
		t.Fatal("invalid OpenConnect server accepted")
	}
}

func TestXrayChannelValidation(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "xray", Installed: true}}
	cfg.Channels = append(cfg.Channels, Channel{
		ID: "xray-test", Index: 3, Name: "Xray", Enabled: true,
		Type: "xray", Mode: "tun", FailMode: "block",
		Config: map[string]any{"mtu": 1400, "outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}}},
	})
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" {
			t.Fatalf("valid Xray channel rejected: %+v", p)
		}
	}
	cfg.Channels[1].Config["outbound"] = map[string]any{"protocol": "unknown", "settings": map[string]any{}}
	if !problem(t, cfg, "outbound.protocol", "неподдерживаемый") {
		t.Fatal("unknown Xray protocol accepted")
	}
}

func TestPolicyMayUseEnabledXrayChannel(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "xray", Installed: true}}
	cfg.Channels = append(cfg.Channels, Channel{
		ID: "xray-test", Index: 3, Name: "Xray", Enabled: true,
		Type: "xray", Mode: "tun", FailMode: "block",
		Config: map[string]any{"outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}}},
	})
	cfg.Policies = []Policy{{ID: "web", Name: "Web", Enabled: true, Priority: 10, Channel: "xray-test", Protocol: "tcp", DstPort: "443"}}
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" {
			t.Fatalf("valid Xray policy rejected: %+v", p)
		}
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

func TestXrayPolicyRejectsLocalICMPReplies(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "xray", Installed: true}, {ID: "wireguard", Installed: true}}
	cfg.Channels = append(cfg.Channels, Channel{
		ID: "xr-policy", Index: 3, Name: "Xray", Enabled: true,
		Type: "xray", Mode: "tun", FailMode: "block",
		Config: map[string]any{"outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}}},
	}, validWireGuardChannel())
	for _, tc := range []struct {
		name, channel, protocol, severity string
		enabled                           bool
	}{
		{"xray ICMP", "xr-policy", "icmp", "error", true},
		{"disabled draft", "xr-policy", "icmp", "warning", false},
		{"xray TCP", "xr-policy", "tcp", "", true},
		{"xray UDP", "xr-policy", "udp", "", true},
		{"xray any", "xr-policy", "any", "", true},
		{"WireGuard ICMP", "wg-home", "icmp", "", true},
		{"direct ICMP", "direct", "icmp", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.Policies = []Policy{{ID: "test", Name: "Test", Enabled: tc.enabled, Channel: tc.channel, Protocol: tc.protocol}}
			severity := ""
			for _, p := range cfg.Validate().Problems {
				if p.Path == "policies[0].protocol" {
					severity = p.Severity
				}
			}
			if severity != tc.severity {
				t.Fatalf("severity=%q, want %q", severity, tc.severity)
			}
		})
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

func TestXrayRejectsLocalICMPHealthProbe(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "xray", Installed: true}}
	cfg.Channels = append(cfg.Channels, Channel{ID: "xr-health", Index: 3, Name: "Xray", Enabled: true, Type: "xray", Mode: "tun", FailMode: "block", Config: map[string]any{"outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}}}})
	for _, kind := range []string{"icmp", "tcp", "http"} {
		target := map[string]string{"icmp": "192.0.2.1", "tcp": "192.0.2.1:443", "http": "https://example.test/health"}[kind]
		cfg.Channels[1].Probe = validProbeOf(kind, target)
		found := false
		for _, p := range cfg.Validate().Problems {
			if p.Severity == "error" && p.Path == "channels[1].probe.type" {
				found = true
			}
		}
		if found != (kind == "icmp") {
			t.Fatalf("%s: rejected=%v", kind, found)
		}
	}
	cfg.Channels[1].Probe = Probe{Type: "icmp"}
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" && p.Path == "channels[1].probe.type" {
			t.Fatalf("disabled probe rejected: %+v", p)
		}
	}
}

package config

import "testing"

func TestDNSUpstreamEndpoints(t *testing.T) {
	tests := []struct {
		up        Upstream
		port      int
		protocols int
	}{
		{Upstream{ID: "plain", Type: "plain", Address: "1.1.1.1"}, 53, 2},
		{Upstream{ID: "plain-custom", Type: "plain", Address: "9.9.9.9:5353"}, 5353, 2},
		{Upstream{ID: "dot", Type: "dot", Address: "1.1.1.1@8853#cloudflare-dns.com"}, 8853, 1},
		{Upstream{ID: "doh", Type: "doh", Address: "https://8.8.8.8/dns-query"}, 443, 1},
		{Upstream{ID: "doq", Type: "doq", Address: "quic://94.140.14.14:853"}, 853, 1},
	}
	for _, tt := range tests {
		got, err := DNSUpstreamEndpoints(tt.up)
		if err != nil {
			t.Fatalf("%s: %v", tt.up.ID, err)
		}
		if len(got) != tt.protocols || got[0].Port != tt.port || !got[0].Address.Is4() {
			t.Fatalf("%s: %+v", tt.up.ID, got)
		}
	}
	if _, err := DNSUpstreamEndpoints(Upstream{Type: "doh", Address: "https://dns.google/dns-query"}); err == nil {
		t.Fatal("hostname-only channel binding accepted")
	}
}

func TestDNSChannelBindingValidation(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "wireguard", Installed: true}}
	cfg.Channels = append(cfg.Channels, validWireGuardChannel())
	cfg.DNS.Upstreams[0].Channel = "wg-home"
	if problem(t, cfg, "dns.upstreams[0].channel", "неизвестный") || problem(t, cfg, "dns.upstreams[0].address", "IPv4") {
		t.Fatalf("valid DNS channel rejected: %+v", cfg.Validate().Problems)
	}

	cfg.DNS.SplitRules = []DNSSplitRule{
		{ID: "direct", Enabled: true, Domains: []string{"one.example"}, Upstream: "up-1", Channel: "direct"},
		{ID: "vpn", Enabled: true, Domains: []string{"two.example"}, Upstream: "up-1", Channel: "wg-home"},
	}
	if !problem(t, cfg, "dns.split_rules[0].channel", "разные каналы") && !problem(t, cfg, "dns.split_rules[1].channel", "разные каналы") {
		t.Fatal("one upstream accepted through conflicting channels")
	}
}

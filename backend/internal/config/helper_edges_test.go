package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRouteDestinationFamilyAllForms(t *testing.T) {
	for _, test := range []struct {
		value string
		is6   bool
		ok    bool
	}{
		{"192.0.2.0/24", false, true},
		{"2001:db8::/32", true, true},
		{"192.0.2.1", false, true},
		{"2001:db8::1", true, true},
		{"default", false, false},
		{"invalid", false, false},
	} {
		is6, ok := routeDestinationFamily(test.value)
		if is6 != test.is6 || ok != test.ok {
			t.Errorf("routeDestinationFamily(%q) = %v,%v, want %v,%v", test.value, is6, ok, test.is6, test.ok)
		}
	}
}

func TestPortSpecContainsRejectsMalformedAndOutOfRangeValues(t *testing.T) {
	for _, spec := range []string{"443", "80, 443", "400-500", "bad,443", "bad-500,443", "400-bad,443"} {
		if !portSpecContains(spec, 443) {
			t.Errorf("%q does not contain 443", spec)
		}
	}
	for _, spec := range []string{"", "bad", "0", "65536", "999999999999999999999999999", "444", "1-442", "500-400"} {
		if portSpecContains(spec, 443) {
			t.Errorf("malformed/outside %q contains 443", spec)
		}
	}
}

func TestDNSBootstrapEverySyntaxAndFailure(t *testing.T) {
	for _, value := range []string{"1.1.1.1", "9.9.9.9:5353"} {
		if err := validateDNSBootstrap(value); err != nil {
			t.Errorf("valid bootstrap %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"", " 1.1.1.1", "dns.example", "2001:db8::1", "1.1.1.1:", "1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1:bad"} {
		if err := validateDNSBootstrap(value); err == nil {
			t.Errorf("invalid bootstrap %q accepted", value)
		}
	}
}

func TestAddressInNetworkAllOutcomes(t *testing.T) {
	cfg := Default()
	cfg.Networks = []Network{
		{ID: "valid", RouterAddress: "192.0.2.1/24"},
		{ID: "broken", RouterAddress: "not-a-prefix"},
	}
	if !cfg.addressInNetwork("valid", netip.MustParseAddr("192.0.2.99")) {
		t.Fatal("address inside network reported outside")
	}
	if cfg.addressInNetwork("valid", netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("address outside network reported inside")
	}
	if cfg.addressInNetwork("broken", netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("broken network accepted")
	}
	if cfg.addressInNetwork("missing", netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("missing network accepted")
	}
}

func TestXrayChannelEveryProtocolAndFailure(t *testing.T) {
	protocols := []string{"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "freedom"}
	for _, protocol := range protocols {
		cfg := Default()
		cfg.Components = []Component{{ID: "xray", Installed: true}}
		cfg.Channels = append(cfg.Channels, Channel{
			ID: "xray", Index: 1, Name: "Xray", Enabled: true, Type: "xray", Mode: "tun", FailMode: "block",
			Config: map[string]any{"mtu": 576, "outbound": map[string]any{"protocol": protocol, "settings": map[string]any{}}},
		})
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("valid Xray protocol %q rejected: %+v", protocol, result.Problems)
		}
	}

	base := func() *Config {
		cfg := Default()
		cfg.Channels = append(cfg.Channels, Channel{
			ID: "xray", Index: 1, Name: "Xray", Enabled: true, Type: "xray", Mode: "tun", FailMode: "block",
			Config: map[string]any{"outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}}},
		})
		return cfg
	}
	for _, test := range []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"mode", "channels[1].mode", func(c *Config) { c.Channels[1].Mode = "socks" }},
		{"MTU low", "channels[1].config.mtu", func(c *Config) { c.Channels[1].Config["mtu"] = 575 }},
		{"MTU high", "channels[1].config.mtu", func(c *Config) { c.Channels[1].Config["mtu"] = 9001 }},
		{"protocol", "channels[1].config.outbound.protocol", func(c *Config) {
			c.Channels[1].Config["outbound"] = map[string]any{"protocol": "unknown", "settings": map[string]any{}}
		}},
		{"missing settings", "channels[1].config.outbound.settings", func(c *Config) { c.Channels[1].Config["outbound"] = map[string]any{"protocol": "freedom"} }},
		{"unknown config", "channels[1].config", func(c *Config) { c.Channels[1].Config["unknown"] = true }},
		{"unencodable", "channels[1].config", func(c *Config) { c.Channels[1].Config["mtu"] = func() {} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := base()
			test.edit(cfg)
			if !hasErrorAt(cfg.Validate(), test.path) {
				t.Fatalf("invalid Xray accepted; expected %s: %s", test.path, strings.TrimSpace(test.name))
			}
		})
	}
}

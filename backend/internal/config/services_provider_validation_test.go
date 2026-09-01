package config

import "testing"

func TestProviderSpecificAdvancedOptionsAreNeverSilentlyIgnored(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"kea DHCP", "dhcp.advanced_options", func(c *Config) { c.DHCP.Provider = "kea"; c.DHCP.AdvancedOptions = "raw" }},
		{"dnsmasq DNS", "dns.advanced_options", func(c *Config) { c.DNS.Provider = "dnsmasq"; c.DNS.AdvancedOptions = "raw" }},
		{"dnsproxy DNS", "dns.advanced_options", func(c *Config) { c.DNS.Provider = "dnsproxy"; c.DNS.AdvancedOptions = "raw" }},
		{"dnsmasq DNSSEC", "dns.dnssec", func(c *Config) { c.DNS.Enabled = true; c.DNS.Provider = "dnsmasq"; c.DNS.DNSSEC = true }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.edit(cfg)
			if !hasErrorAt(cfg.Validate(), tc.path) {
				t.Fatalf("missing error at %s", tc.path)
			}
		})
	}

	for _, edit := range []func(*Config){
		func(c *Config) { c.DHCP.Provider = "dnsmasq"; c.DHCP.AdvancedOptions = "dhcp-option=42,192.0.2.1" },
		func(c *Config) {
			c.DHCP.Provider = "isc-dhcp-server"
			c.DHCP.AdvancedOptions = "option ntp-servers 192.0.2.1;"
		},
		func(c *Config) { c.DNS.Provider = "unbound"; c.DNS.AdvancedOptions = "    serve-expired: yes" },
	} {
		cfg := Default()
		edit(cfg)
		result := cfg.Validate()
		if hasErrorAt(result, "dhcp.advanced_options") || hasErrorAt(result, "dns.advanced_options") {
			t.Fatalf("supported advanced options rejected: %#v", result)
		}
	}
}

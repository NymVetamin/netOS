package config

import "testing"

func validDDNSConfig(provider string) *Config {
	cfg := Default()
	hostname := "router.example.test"
	if provider == "duckdns" {
		hostname = "router.duckdns.org"
	}
	cfg.DDNS = DDNS{
		Enabled: true, Provider: provider, Hostname: hostname, AddressSource: "web", Interval: 300,
		Token: "safe-token", ZoneID: "safe_zone", RecordID: "safe-record", Username: "safe-user", Password: "safe-password",
	}
	return cfg
}

func TestDuckDNSRequiresOwnedTopLevelSubdomainName(t *testing.T) {
	for _, hostname := range []string{"router.example.test", "nested.router.duckdns.org", "duckdns.org"} {
		cfg := validDDNSConfig("duckdns")
		cfg.DDNS.Hostname = hostname
		if result := cfg.Validate(); !result.HasErrors() {
			t.Fatalf("DuckDNS hostname %q was accepted", hostname)
		}
	}
	for _, hostname := range []string{"router.duckdns.org", "ROUTER.duckdns.org"} {
		cfg := validDDNSConfig("duckdns")
		cfg.DDNS.Hostname = hostname
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("DuckDNS hostname %q was rejected: %+v", hostname, result.Problems)
		}
	}
}

func TestDDNSProviderConfigurations(t *testing.T) {
	for _, provider := range []string{"duckdns", "cloudflare", "noip"} {
		cfg := validDDNSConfig(provider)
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("provider %s rejected: %+v", provider, result.Problems)
		}
	}
}

func TestDDNSRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"invalid hostname", func(c *Config) { c.DDNS.Hostname = "bad_name.example" }},
		{"hostname control", func(c *Config) { c.DDNS.Hostname = "good.example\nforged" }},
		{"token control", func(c *Config) { c.DDNS.Token = "token\r\nHeader: value" }},
		{"cloudflare zone path", func(c *Config) { c.DDNS.Provider, c.DDNS.ZoneID = "cloudflare", "../zone" }},
		{"cloudflare record control", func(c *Config) { c.DDNS.Provider, c.DDNS.RecordID = "cloudflare", "record\n" }},
		{"noip colon username", func(c *Config) { c.DDNS.Provider, c.DDNS.Username = "noip", "user:other" }},
		{"noip password control", func(c *Config) { c.DDNS.Provider, c.DDNS.Password = "noip", "pass\nword" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validDDNSConfig("duckdns")
			tc.mutate(cfg)
			if result := cfg.Validate(); !result.HasErrors() {
				t.Fatal("unsafe DDNS configuration was accepted")
			}
		})
	}
}

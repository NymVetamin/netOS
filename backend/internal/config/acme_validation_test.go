package config

import "testing"

func validACMEConfig() *Config {
	cfg := Default()
	cfg.System.Panel.TLS = TLS{Mode: "acme", Domain: "router.acme-valid.com", Email: "admin@example.org", AcceptTOS: true}
	return cfg
}

func TestACMEValidationMatrix(t *testing.T) {
	if result := validACMEConfig().Validate(); result.HasErrors() {
		t.Fatalf("valid ACME rejected: %+v", result.Problems)
	}
	tests := []struct {
		name string
		edit func(*Config)
		path string
	}{
		{"missing domain", func(c *Config) { c.System.Panel.TLS.Domain = "" }, "system.panel.tls.domain"},
		{"single label", func(c *Config) { c.System.Panel.TLS.Domain = "router" }, "system.panel.tls.domain"},
		{"IP literal", func(c *Config) { c.System.Panel.TLS.Domain = "192.0.2.1" }, "system.panel.tls.domain"},
		{"reserved local", func(c *Config) { c.System.Panel.TLS.Domain = "router.local" }, "system.panel.tls.domain"},
		{"reserved test", func(c *Config) { c.System.Panel.TLS.Domain = "router.example.test" }, "system.panel.tls.domain"},
		{"reserved example.org", func(c *Config) { c.System.Panel.TLS.Domain = "router.example.org" }, "system.panel.tls.domain"},
		{"reserved home.arpa", func(c *Config) { c.System.Panel.TLS.Domain = "router.home.arpa" }, "system.panel.tls.domain"},
		{"unknown public suffix", func(c *Config) { c.System.Panel.TLS.Domain = "router.not-a-real-tld" }, "system.panel.tls.domain"},
		{"public suffix itself", func(c *Config) { c.System.Panel.TLS.Domain = "co.uk" }, "system.panel.tls.domain"},
		{"unsafe domain", func(c *Config) { c.System.Panel.TLS.Domain = "router.acme-valid.com\nnext" }, "system.panel.tls.domain"},
		{"bad email", func(c *Config) { c.System.Panel.TLS.Email = "Admin <admin@example.org>" }, "system.panel.tls.email"},
		{"unsafe email", func(c *Config) { c.System.Panel.TLS.Email = "admin@example.org\nnext" }, "system.panel.tls.email"},
		{"TOS not accepted", func(c *Config) { c.System.Panel.TLS.AcceptTOS = false }, "system.panel.tls.accept_tos"},
		{"HTTP challenge collision", func(c *Config) { c.System.Panel.Port = 80 }, "system.panel.port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validACMEConfig()
			tc.edit(cfg)
			if !hasErrorAt(cfg.Validate(), tc.path) {
				t.Fatalf("missing %s error: %+v", tc.path, cfg.Validate().Problems)
			}
		})
	}
}

func TestACMEEmailIsOptionalAndDomainCanonicalVariantsAreAccepted(t *testing.T) {
	for _, domain := range []string{"ROUTER.ACME-VALID.COM", "router.acme-valid.com."} {
		cfg := validACMEConfig()
		cfg.System.Panel.TLS.Domain, cfg.System.Panel.TLS.Email = domain, ""
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("domain %q rejected: %+v", domain, result.Problems)
		}
	}
}

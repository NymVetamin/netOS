package config

import "testing"

func TestACMEContactsForSharedDomain(t *testing.T) {
	const domain = "router.acme-valid.com"
	const email = "admin@example.org"
	for _, tc := range []struct {
		name, panel, vpn, vpnDomain, mode string
		enabled, conflict                 bool
	}{
		{"same account", email, email, "ROUTER.ACME-VALID.COM.", "acme", true, false},
		{"different accounts", email, "other@example.org", "ROUTER.ACME-VALID.COM.", "acme", true, true},
		{"both without email", "", "", domain, "acme", true, false},
		{"one without email", "", email, domain, "acme", true, true},
		{"separate domains", email, "other@example.org", "vpn.acme-valid.com", "acme", true, false},
		{"disabled service", email, "other@example.org", domain, "acme", false, false},
		{"using panel certificate", email, "other@example.org", domain, "panel", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validOcservConfig()
			cfg.System.Panel.TLS = TLS{Mode: "acme", Domain: domain, Email: tc.panel, AcceptTOS: true}
			server := &cfg.VPNServers[0]
			server.Enabled = tc.enabled
			server.Config["public_endpoint"] = domain + ":443"
			if tc.vpnDomain == "vpn.acme-valid.com" {
				server.Config["public_endpoint"] = tc.vpnDomain + ":443"
			}
			server.Config["tls"] = map[string]any{"mode": tc.mode, "domain": tc.vpnDomain, "email": tc.vpn, "accept_tos": true}
			result := cfg.Validate()
			if hasErrorAt(result, "vpn_servers[0].config.tls.email") != tc.conflict || result.HasErrors() != tc.conflict {
				t.Fatalf("unexpected validation: %+v", result.Problems)
			}
		})
	}
}

func TestACMEContactsAcrossVPNsAndEdits(t *testing.T) {
	cfg := validOcservConfig()
	first := &cfg.VPNServers[0]
	const domain = "vpn.acme-valid.com"
	first.Config["public_endpoint"] = domain + ":443"
	first.Config["tls"] = map[string]any{"mode": "acme", "domain": domain, "email": "one@example.org", "accept_tos": true}
	second := VPNServer{ID: "other", Index: 2, Name: "Second", Enabled: true, Type: "ocserv", Port: 4450, Subnet: "10.22.0.1/24",
		Config: map[string]any{"public_endpoint": domain + ":4450", "tls": map[string]any{"mode": "acme", "domain": domain, "email": "two@example.org", "accept_tos": true}}}
	cfg.VPNServers = append(cfg.VPNServers, second)
	if result := cfg.Validate(); !hasErrorAt(result, "vpn_servers[1].config.tls.email") {
		t.Fatalf("missing conflict: %+v", result.Problems)
	}
	cfg.VPNServers[0].Config["tls"].(map[string]any)["email"] = "two@example.org"
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("corrected contact rejected: %+v", result.Problems)
	}
}

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

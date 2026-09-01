package config

import "testing"

func validDomainPolicyConfig() *Config {
	cfg := Default()
	cfg.DNS.Enabled = true
	cfg.DNS.Provider = "dnsmasq"
	cfg.Components = append(cfg.Components, Component{ID: "dnsmasq", Installed: true})
	cfg.Policies = []Policy{{ID: "domains", Name: "Domains", Enabled: true, Priority: 10, Channel: "direct", Domains: []string{"example.com", "CDN.Example.NET."}}}
	return cfg
}

func TestPolicyDomainsValidationMatrix(t *testing.T) {
	if result := validDomainPolicyConfig().Validate(); result.HasErrors() {
		t.Fatalf("valid domains rejected: %+v", result.Problems)
	}
	tests := []struct {
		name string
		edit func(*Config)
		path string
	}{
		{"empty", func(c *Config) { c.Policies[0].Domains = []string{""} }, "policies[0].domains[0]"},
		{"space", func(c *Config) { c.Policies[0].Domains = []string{"bad domain.example"} }, "policies[0].domains[0]"},
		{"underscore", func(c *Config) { c.Policies[0].Domains = []string{"bad_domain.example"} }, "policies[0].domains[0]"},
		{"duplicate case and dot", func(c *Config) { c.Policies[0].Domains = []string{"Example.COM", "example.com."} }, "policies[0].domains[1]"},
		{"DNS disabled", func(c *Config) { c.DNS.Enabled = false }, "policies[0].domains"},
		{"AAAA allowed", func(c *Config) { c.IPv6.FilterAAAA = false }, "policies[0].domains"},
		{"backend port collision", func(c *Config) {
			c.DNS.Provider = "unbound"
			c.DNS.Port = 5355
			c.Components = append(c.Components, Component{ID: "unbound", Installed: true})
		}, "dns.port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validDomainPolicyConfig()
			tc.edit(cfg)
			if result := cfg.Validate(); !hasErrorAt(result, tc.path) {
				t.Fatalf("missing error at %s: %+v", tc.path, result.Problems)
			}
		})
	}
}

func TestDisabledAndXrayInboundDomainPoliciesDoNotRequireDNS(t *testing.T) {
	cfg := Default()
	cfg.Policies = []Policy{{ID: "future", Name: "Future", Channel: "direct", Domains: []string{"example.com"}}}
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("disabled policy rejected: %+v", result.Problems)
	}
	cfg.VPNServers = []VPNServer{{ID: "reality", Index: 1, Name: "Reality", Type: "xray", Subnet: "10.9.0.1/24"}}
	cfg.Policies[0].Enabled = true
	cfg.Policies[0].VPNServer = "reality"
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("Xray-native domain policy rejected: %+v", result.Problems)
	}
}

func TestPolicyDomainCountLimit(t *testing.T) {
	cfg := validDomainPolicyConfig()
	cfg.Policies[0].Domains = make([]string, 129)
	for i := range cfg.Policies[0].Domains {
		cfg.Policies[0].Domains[i] = "d" + string(rune('a'+i%26)) + ".example.com"
	}
	if result := cfg.Validate(); !hasErrorAt(result, "policies[0].domains") {
		t.Fatalf("domain limit accepted: %+v", result.Problems)
	}
}

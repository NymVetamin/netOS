package config

import "testing"

func validationFixture() *Config {
	cfg := Default()
	cfg.Interfaces = []Interface{{ID: "lan", Name: "lan0", Type: "physical", Enabled: true}}
	cfg.Networks = []Network{{
		ID: "home", Name: "Home", Interface: "lan", RouterAddress: "192.168.50.1/24", Zone: "lan", Enabled: true,
		DHCPPool: DHCPPool{Enabled: true, Start: "192.168.50.100", End: "192.168.50.200", LeaseTime: 3600},
	}}
	cfg.DHCP.Enabled = false
	return cfg
}

func TestValidationRejectsUnsafeDHCPFieldsAndInvalidPool(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"router-inside-pool", "networks[0].dhcp_pool", func(c *Config) { c.Networks[0].DHCPPool.Start = "192.168.50.1" }},
		{"broadcast", "networks[0].dhcp_pool", func(c *Config) { c.Networks[0].DHCPPool.End = "192.168.50.255" }},
		{"ipv6-dns", "networks[0].dhcp_pool.dns_servers", func(c *Config) { c.Networks[0].DHCPPool.DNSServers = []string{"::1"} }},
		{"foreign-gateway", "networks[0].dhcp_pool.gateway", func(c *Config) { c.Networks[0].DHCPPool.Gateway = "10.0.0.1" }},
		{"domain-injection", "networks[0].dhcp_pool.domain", func(c *Config) { c.Networks[0].DHCPPool.Domain = "lan\ninterface: evil" }},
		{"option-code", "networks[0].dhcp_pool.options", func(c *Config) { c.Networks[0].DHCPPool.Options = map[string]string{"999": "x"} }},
		{"option-injection", "networks[0].dhcp_pool.options", func(c *Config) { c.Networks[0].DHCPPool.Options = map[string]string{"66": "ok\ndhcp-range=evil"} }},
		{"reservation-ipv6", "dhcp.reservations[0].ip", func(c *Config) {
			c.DHCP.Reservations = []Reservation{{ID: "r1", MAC: "02:00:00:00:00:01", IP: "::1", Network: "home"}}
		}},
		{"reservation-hostname", "dhcp.reservations[0].hostname", func(c *Config) {
			c.DHCP.Reservations = []Reservation{{ID: "r1", MAC: "02:00:00:00:00:01", IP: "192.168.50.10", Network: "home", Hostname: "bad name"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validationFixture()
			tt.edit(cfg)
			if !hasErrorAt(cfg.Validate(), tt.path) {
				t.Fatalf("unsafe configuration accepted; wanted error at %s", tt.path)
			}
		})
	}
}

func TestValidationRejectsUnsafeAndMalformedDNS(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"port", "dns.port", func(c *Config) { c.DNS.Port = 70000 }},
		{"cache", "dns.cache_size", func(c *Config) { c.DNS.CacheSize = -1 }},
		{"local-domain", "dns.local_domain", func(c *Config) { c.DNS.LocalDomain = "bad domain" }},
		{"bootstrap-host", "dns.bootstrap[0]", func(c *Config) { c.DNS.Bootstrap = []string{"resolver.example"} }},
		{"upstream-injection", "dns.upstreams[0].address", func(c *Config) {
			c.DNS.Provider = "dnsmasq"
			c.DNS.Upstreams[0].Address = "1.1.1.1\naddress=/evil/1.2.3.4"
		}},
		{"wrong-scheme", "dns.upstreams[0].address", func(c *Config) {
			c.DNS.Provider = "dnsproxy"
			c.DNS.Upstreams[0].Type = "doh"
			c.DNS.Upstreams[0].Address = "http://dns.example/query"
		}},
		{"record-a", "dns.static_records[0].value", func(c *Config) {
			c.DNS.StaticRecords = []DNSRecord{{ID: "r", Type: "A", Name: "host.lan", Value: "::1"}}
		}},
		{"record-name-injection", "dns.static_records[0].name", func(c *Config) {
			c.DNS.StaticRecords = []DNSRecord{{ID: "r", Type: "A", Name: "host\nserver=evil", Value: "192.168.50.2"}}
		}},
		{"record-srv", "dns.static_records[0].value", func(c *Config) {
			c.DNS.StaticRecords = []DNSRecord{{ID: "r", Type: "SRV", Name: "_sip._tcp.lan", Value: "bad"}}
		}},
		{"record-mx", "dns.static_records[0].value", func(c *Config) {
			c.DNS.StaticRecords = []DNSRecord{{ID: "r", Type: "MX", Name: "lan", Value: "10 bad name"}}
		}},
		{"split-domain", "dns.split_rules[0].domains", func(c *Config) {
			c.DNS.SplitRules = []DNSSplitRule{{ID: "s", Enabled: true, Domains: []string{"lan\nserver=evil"}, Upstream: "up-1"}}
		}},
		{"split-disabled-upstream", "dns.split_rules[0].upstream", func(c *Config) {
			c.DNS.Upstreams[0].Enabled = false
			c.DNS.SplitRules = []DNSSplitRule{{ID: "s", Enabled: true, Domains: []string{"corp.lan"}, Upstream: "up-1"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validationFixture()
			tt.edit(cfg)
			if !hasErrorAt(cfg.Validate(), tt.path) {
				t.Fatalf("unsafe configuration accepted; wanted error at %s: %#v", tt.path, cfg.Validate().Problems)
			}
		})
	}
}

func TestValidationAcceptsAllSupportedStaticDNSRecords(t *testing.T) {
	cfg := validationFixture()
	cfg.DNS.StaticRecords = []DNSRecord{
		{ID: "a", Type: "A", Name: "host.lan", Value: "192.168.50.2"},
		{ID: "cname", Type: "CNAME", Name: "alias.lan", Value: "host.lan"},
		{ID: "txt", Type: "TXT", Name: "text.lan", Value: "hello"},
		{ID: "srv", Type: "SRV", Name: "_sip._tcp.lan", Value: "10 20 5060 sip.lan"},
		{ID: "mx", Type: "MX", Name: "lan", Value: "10 mail.lan"},
	}
	if result := cfg.Validate(); hasErrorAt(result, "dns.static_records") {
		t.Fatalf("valid records rejected: %#v", result.Problems)
	}
}

package config

import (
	"strings"
	"testing"
)

func hasRemainingProblem(cfg *Config, path, severity string) bool {
	for _, p := range cfg.Validate().Problems {
		if strings.HasPrefix(p.Path, path) && p.Severity == severity {
			return true
		}
	}
	return false
}

func TestRemainingStaticGatewayWarning(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{{ID: "lan", Name: "eth1", Type: "physical", Enabled: true}}
	cfg.Networks = []Network{{ID: "lan", Name: "LAN", Enabled: true, Interface: "lan", RouterAddress: "10.60.1.1/24"}}
	cfg.Routing.Static = []StaticRoute{{ID: "r", Name: "test", Enabled: true, Destination: "10.77.0.0/24", Gateway: "172.31.99.1"}}
	if !hasRemainingProblem(cfg, "routing.static[0].gateway", "warning") {
		t.Fatal("unverified gateway has no warning")
	}
	cfg.Routing.Static[0].Gateway = "10.60.1.2"
	if hasRemainingProblem(cfg, "routing.static[0].gateway", "warning") {
		t.Fatal("connected gateway warned")
	}
	cfg.Routing.Static[0].Gateway = "172.31.99.1"
	cfg.Routing.Static[0].Enabled = false
	if hasRemainingProblem(cfg, "routing.static[0].gateway", "warning") {
		t.Fatal("disabled route warned")
	}
}

func TestRemainingDNSHostnameValidation(t *testing.T) {
	for _, provider := range []string{"unbound"} {
		if err := validateDNSUpstreamAddress(provider, Upstream{Type: "plain", Address: "not-an-ip", Enabled: true}); err == nil {
			t.Errorf("%s accepts non-IP upstream", provider)
		}
		if err := validateDNSUpstreamAddress(provider, Upstream{Type: "plain", Address: "1.1.1.1", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Default()
	cfg.DNS.Enabled = true
	cfg.DNS.Provider = "dnsmasq"
	cfg.DNS.Upstreams = []Upstream{{ID: "dns", Type: "plain", Address: "not-an-ip", Enabled: true}}
	if !hasRemainingProblem(cfg, "dns.upstreams[0].address", "warning") {
		t.Fatal("hostname bootstrap dependency is silent")
	}
	if err := validateDNSUpstreamAddress("dnsmasq", cfg.DNS.Upstreams[0]); err != nil {
		t.Fatal("valid hostname rejected", err)
	}
	if err := validateDNSUpstreamAddress("dnsproxy", Upstream{Type: "doh", Address: "https://dns.example/dns-query", Enabled: true}); err != nil {
		t.Fatal(err)
	}
}

func TestRemainingVPNSubnetOverlap(t *testing.T) {
	cfg := validWGServerConfig()
	cfg.Interfaces = []Interface{{ID: "lan", Name: "eth1", Type: "physical", Enabled: true}}
	cfg.Networks = []Network{{ID: "lan", Name: "LAN", Enabled: true, Interface: "lan", RouterAddress: "10.9.0.1/24"}}
	if !hasRemainingProblem(cfg, "vpn_servers[0].subnet", "error") {
		t.Fatal("overlapping LAN/VPN accepted")
	}
	cfg.Networks[0].RouterAddress = "10.9.1.1/24"
	if hasRemainingProblem(cfg, "vpn_servers[0].subnet", "error") {
		t.Fatal("disjoint subnets rejected")
	}
	cfg.Networks[0].RouterAddress = "10.9.0.1/24"
	cfg.VPNServers[0].Enabled = false
	if hasRemainingProblem(cfg, "vpn_servers[0].subnet", "error") {
		t.Fatal("disabled VPN prevents staging")
	}
	cfg.VPNServers[0].Enabled = true
	cfg.Networks[0].Enabled = false
	if hasRemainingProblem(cfg, "vpn_servers[0].subnet", "error") {
		t.Fatal("disabled LAN prevents staging")
	}
	cfg.Networks[0].Enabled = true
	cfg.Networks[0].RouterAddress = "10.9.0.129/25"
	if !hasRemainingProblem(cfg, "vpn_servers[0].subnet", "error") {
		t.Fatal("nested subnets accepted")
	}
	cfg.Networks = nil
	other := cfg.VPNServers[0]
	other.ID, other.Index = "other", 2
	cfg.VPNServers = append(cfg.VPNServers, other)
	if !hasRemainingProblem(cfg, "vpn_servers[1].subnet", "error") {
		t.Fatal("overlapping VPN servers accepted")
	}
}

func TestRemainingDNSWithoutUpstreams(t *testing.T) {
	for _, provider := range []string{"dnsmasq", "dnsproxy", "unbound"} {
		cfg := Default()
		cfg.DNS.Enabled = true
		cfg.DNS.Provider = provider
		cfg.DNS.Upstreams = nil
		want := provider != "unbound"
		if got := hasRemainingProblem(cfg, "dns.upstreams", "warning"); got != want {
			t.Errorf("%s warning=%v want=%v", provider, got, want)
		}
		cfg.DNS.Upstreams = []Upstream{{ID: "dns", Type: "plain", Address: "1.1.1.1", Enabled: false}}
		if got := hasRemainingProblem(cfg, "dns.upstreams", "warning"); got != want {
			t.Errorf("%s disabled upstream warning=%v want=%v", provider, got, want)
		}
		cfg.DNS.Enabled = false
		if hasRemainingProblem(cfg, "dns.upstreams", "warning") {
			t.Fatal("disabled DNS warned")
		}
	}
}

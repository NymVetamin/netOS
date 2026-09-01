package config

import (
	"reflect"
	"testing"
)

func TestCatalogAndDefaultHelpersContract(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{
		{ID: "kea", Installed: true},
		{ID: "dnsmasq", Installed: false},
		{ID: "isc-dhcp-server", Installed: true},
		{ID: "unknown", Installed: true},
	}
	if got, want := cfg.ProvidersFor("dhcp"), []string{"kea", "isc-dhcp-server"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DHCP providers = %v, want %v", got, want)
	}
	if got := cfg.ProvidersFor("missing-role"); len(got) != 0 {
		t.Fatalf("unknown role has providers: %v", got)
	}

	pool := DefaultDHCPPool("192.0.2.10", "192.0.2.20")
	if !pool.Enabled || pool.Start != "192.0.2.10" || pool.End != "192.0.2.20" || pool.LeaseTime != 43200 {
		t.Fatalf("default DHCP pool = %+v", pool)
	}

	problem := Problem{Path: "dns.port", Message: "bad"}
	if got := problem.Error(); got != "dns.port: bad" {
		t.Fatalf("Problem.Error() = %q", got)
	}
}

func TestDNSChannelBindingsContract(t *testing.T) {
	cfg := Default()
	cfg.DNS.Upstreams = []Upstream{
		{ID: "own", Type: "plain", Address: "1.1.1.1", Channel: "vpn-a", Enabled: true},
		{ID: "split", Type: "plain", Address: "9.9.9.9:5353", Enabled: true},
		{ID: "direct", Type: "plain", Address: "8.8.8.8", Channel: "direct", Enabled: true},
		{ID: "disabled", Type: "plain", Address: "8.8.4.4", Channel: "vpn-a"},
		{ID: "invalid", Type: "dot", Address: "dns.example", Channel: "vpn-a", Enabled: true},
	}
	cfg.DNS.SplitRules = []DNSSplitRule{
		{ID: "active", Enabled: true, Upstream: "split", Channel: "vpn-b"},
		{ID: "disabled", Upstream: "direct", Channel: "vpn-b"},
	}

	bindings := cfg.DNSChannelBindings()
	if len(bindings) != 4 {
		t.Fatalf("bindings = %+v, want two sockets for each of two upstreams", bindings)
	}
	counts := map[string]int{}
	for _, binding := range bindings {
		counts[binding.UpstreamID+"/"+binding.ChannelID]++
		if binding.Protocol != "udp" && binding.Protocol != "tcp" {
			t.Fatalf("unexpected protocol: %+v", binding)
		}
	}
	if counts["own/vpn-a"] != 2 || counts["split/vpn-b"] != 2 || len(counts) != 2 {
		t.Fatalf("binding ownership = %v", counts)
	}
}

func TestInterfaceRelationshipAndVLANNameHelpers(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{
		{ID: "port-a", Name: "eth0", Type: "physical"},
		{ID: "port-b", Name: "eth1", Type: "physical"},
		{ID: "bridge", Name: "br0", Type: "bridge", Members: []string{"port-a"}},
		{ID: "bond", Name: "bond0", Type: "bond", Members: []string{"port-b"}},
	}
	if master, ok := cfg.MasterOf("port-a"); !ok || master.ID != "bridge" {
		t.Fatalf("bridge master = %+v, %v", master, ok)
	}
	if master, ok := cfg.MasterOf("port-b"); !ok || master.ID != "bond" {
		t.Fatalf("bond master = %+v, %v", master, ok)
	}
	for _, id := range []string{"", "missing", "bridge"} {
		if master, ok := cfg.MasterOf(id); ok {
			t.Fatalf("unexpected master for %q: %+v", id, master)
		}
	}

	if got := DefaultVLANName("", 10); got != "" {
		t.Fatalf("empty parent VLAN name = %q", got)
	}
	if got := DefaultVLANName("eth0", 10); got != "eth0.10" {
		t.Fatalf("short VLAN name = %q", got)
	}
	if got := DefaultVLANName("verylongparentname", 4094); got != "verylongpa.4094" || len(got) != maxInterfaceName {
		t.Fatalf("truncated VLAN name = %q (%d)", got, len(got))
	}
}

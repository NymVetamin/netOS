package config

import (
	"fmt"
	"testing"
)

func validDestinationNATConfig() *Config {
	cfg := Default()
	cfg.Interfaces = []Interface{{ID: "wan-if", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.Firewall.NAT = []NATRule{{
		ID: "forward", Name: "web", Enabled: true, Direction: "destination", Interface: "eth0",
		Protocol: "tcpudp", ExtPort: "8000-8010", DestIP: "192.0.2.10", DestPort: "9000-9010", AllowFrom: "198.51.100.0/24",
	}}
	return cfg
}

func hasNATErrorAt(result *ValidationResult, path string) bool {
	for _, problem := range result.Problems {
		if problem.Path == path && problem.Severity == "error" {
			return true
		}
	}
	return false
}

func TestDestinationNATAcceptsSinglePortOrAscendingRange(t *testing.T) {
	for _, ports := range [][2]string{{"443", "8443"}, {"8000-8010", "9000-9010"}, {"53", ""}} {
		cfg := validDestinationNATConfig()
		cfg.Firewall.NAT[0].ExtPort, cfg.Firewall.NAT[0].DestPort = ports[0], ports[1]
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("ports %q/%q rejected: %+v", ports[0], ports[1], result.Problems)
		}
	}
}

func TestDestinationNATRejectsMissingListReverseAndInjectedInterface(t *testing.T) {
	tests := []struct {
		name, field string
		mutate      func(*NATRule)
	}{
		{"missing external port", "firewall.nat[0].ext_port", func(n *NATRule) { n.ExtPort = "" }},
		{"external list", "firewall.nat[0].ext_port", func(n *NATRule) { n.ExtPort = "80,443" }},
		{"destination list", "firewall.nat[0].dest_port", func(n *NATRule) { n.DestPort = "8080,8443" }},
		{"reverse external range", "firewall.nat[0].ext_port", func(n *NATRule) { n.ExtPort = "9000-8000" }},
		{"reverse destination range", "firewall.nat[0].dest_port", func(n *NATRule) { n.DestPort = "9000-8000" }},
		{"ruleset interface injection", "firewall.nat[0].interface", func(n *NATRule) { n.Interface = "eth0 -j ACCEPT" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validDestinationNATConfig()
			tc.mutate(&cfg.Firewall.NAT[0])
			result := cfg.Validate()
			if !hasNATErrorAt(result, tc.field) {
				t.Fatalf("missing error at %s: %+v", tc.field, result.Problems)
			}
		})
	}
}

func TestGenericPortSpecificationsRejectDescendingRanges(t *testing.T) {
	cfg := validDestinationNATConfig()
	index := len(cfg.Firewall.Rules)
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, FirewallRule{
		ID: "bad-range", Name: "bad", Enabled: true, Zone: "global", Flow: "out", Action: "accept", Protocol: "tcp", DstPort: "9000-8000",
	})
	result := cfg.Validate()
	if !hasNATErrorAt(result, fmt.Sprintf("firewall.rules[%d].dst_port", index)) {
		t.Fatalf("descending generic range accepted: %+v", result.Problems)
	}
}

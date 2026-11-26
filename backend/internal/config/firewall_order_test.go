package config

import (
	"strings"
	"testing"
)

func TestLANForwardDenyAfterDefaultAllow(t *testing.T) {
	for _, tc := range []struct {
		name         string
		change       func(*FirewallRule, *FirewallRule)
		before, warn bool
	}{
		{name: "deny below", warn: true},
		{name: "deny above", before: true},
		{name: "disabled allow", change: func(a, d *FirewallRule) { a.Enabled = false }},
		{name: "restricted allow", change: func(a, d *FirewallRule) { a.SrcIP = "192.0.2.2" }},
		{name: "scheduled allow", change: func(a, d *FirewallRule) { a.Schedule = &Schedule{TimeStart: "09:00", TimeStop: "11:00"} }},
		{name: "disabled deny", change: func(a, d *FirewallRule) { d.Enabled = false }},
		{name: "other direction", change: func(a, d *FirewallRule) { d.Zone, d.DstZone = "wan", "lan" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			var allow FirewallRule
			for _, rule := range c.Firewall.Rules {
				if rule.ID == RuleLANOut {
					allow = rule
				}
			}
			deny := FirewallRule{ID: "test-deny", Name: "Запрет", Enabled: true, Zone: "lan", Flow: "forward", DstZone: "wan", Action: "reject", Protocol: "tcp", DstPort: "443"}
			if tc.change != nil {
				tc.change(&allow, &deny)
			}
			c.Firewall.Rules = []FirewallRule{allow, deny}
			if tc.before {
				c.Firewall.Rules = []FirewallRule{deny, allow}
			}
			found := false
			for _, p := range c.Validate().Problems {
				if p.Severity == "warning" && strings.Contains(p.Message, "Запрет") {
					found = true
					if p.Path != "firewall.rules[1]" {
						t.Fatalf("warning on wrong rule: %s", p.Path)
					}
				}
			}
			if found != tc.warn {
				t.Fatalf("warning=%v, want %v", found, tc.warn)
			}
		})
	}
}

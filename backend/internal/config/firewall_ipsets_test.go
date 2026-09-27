package config

import (
	"strings"
	"testing"
)

func TestFirewallAddressSetValidation(t *testing.T) {
	makeConfig := func() *Config {
		c := Default()
		c.Components = append(c.Components, Component{ID: "ipset", Installed: true})
		c.Firewall.IPSets = []FirewallIPSet{{ID: "deny", Name: "Denied", Entries: []string{"192.0.2.1", "198.51.100.2/24"}}}
		c.Firewall.Rules = append(c.Firewall.Rules, FirewallRule{ID: "set-rule", Name: "Set rule", Enabled: true, Zone: "lan", Flow: "forward", Action: "drop", DstIPSet: "deny"})
		return c
	}
	check := func(c *Config) bool {
		for _, p := range c.Validate().Problems {
			if strings.HasPrefix(p.Path, "firewall.") && p.Severity == "error" {
				return true
			}
		}
		return false
	}
	if check(makeConfig()) {
		t.Fatal("valid set rejected")
	}
	for _, entry := range []string{"::1", "0.0.0.0/0", "192.0.2.1\nflush", "192.0.2.1 timeout 0", ""} {
		c := makeConfig()
		c.Firewall.IPSets[0].Entries = []string{entry}
		if !check(c) {
			t.Errorf("unsafe entry accepted: %q", entry)
		}
	}
	c := makeConfig()
	c.Firewall.IPSets = nil
	if !check(c) {
		t.Fatal("dangling reference accepted")
	}
	c = makeConfig()
	c.Components = nil
	if !check(c) {
		t.Fatal("missing component accepted")
	}
	c = makeConfig()
	c.Firewall.IPSets = append(c.Firewall.IPSets, c.Firewall.IPSets[0])
	if !check(c) {
		t.Fatal("duplicate set accepted")
	}
	c = makeConfig()
	c.Firewall.IPSets[0].Entries = nil
	if check(c) {
		t.Fatal("empty deny set rejected")
	}
}

func TestEmptyAddressSetCannotGrantManagement(t *testing.T) {
	c := Default()
	c.Firewall.IPSets = []FirewallIPSet{{ID: "empty", Name: "Empty"}}
	r := FirewallRule{Enabled: true, Action: "accept", Flow: "in", Zone: "global", SrcIPSet: "empty"}
	if c.ruleGrantsManagement(r) {
		t.Fatal("empty selector counted as management access")
	}
}

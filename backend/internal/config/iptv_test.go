package config

import "testing"

func TestIPTVValidation(t *testing.T) {
	fixture := func() *Config {
		c := Default()
		c.Components = append(c.Components, Component{ID: "igmpproxy", Installed: true})
		c.Interfaces = []Interface{{ID: "up", Name: "eth0.20", Type: "vlan", Enabled: true}, {ID: "lan", Name: "br0", Type: "bridge", Enabled: true}}
		c.WANs = []WAN{{ID: "wan", Interface: "up", Enabled: true, Proto: "dhcp"}}
		c.Networks = []Network{{ID: "lan", Interface: "lan", Enabled: true, RouterAddress: "10.99.0.1/24"}}
		c.IPTV = IPTV{Enabled: true, Upstream: "wan", Networks: []string{"lan"}, Sources: []string{"192.0.2.0/24"}}
		return c
	}
	c := fixture()
	r := &ValidationResult{}
	c.validateIPTV(r)
	if r.HasErrors() {
		t.Fatal(r.Problems)
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"component", func(c *Config) { c.Components = nil }},
		{"missing upstream", func(c *Config) { c.IPTV.Upstream = "missing" }},
		{"PPP", func(c *Config) { c.WANs[0].Proto = "pppoe" }},
		{"disabled upstream", func(c *Config) { c.WANs[0].Enabled = false }},
		{"disabled link", func(c *Config) { c.Interfaces[0].Enabled = false }},
		{"no viewers", func(c *Config) { c.IPTV.Networks = nil }},
		{"unknown LAN", func(c *Config) { c.IPTV.Networks = []string{"unknown"} }},
		{"duplicate LAN", func(c *Config) { c.IPTV.Networks = []string{"lan", "lan"} }},
		{"same link", func(c *Config) { c.Networks[0].Interface = "up" }},
		{"invalid source", func(c *Config) { c.IPTV.Sources = []string{"0.0.0.0/0\nquickleave"} }},
		{"multicast source", func(c *Config) { c.IPTV.Sources = []string{"239.0.0.0/8"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixture()
			tc.edit(c)
			r := &ValidationResult{}
			c.validateIPTV(r)
			if !r.HasErrors() {
				t.Fatal("invalid IPTV accepted")
			}
		})
	}
	c = fixture()
	c.IPTV.Enabled = false
	c.IPTV.Upstream = ""
	c.IPTV.Networks = nil
	r = &ValidationResult{}
	c.validateIPTV(r)
	if r.HasErrors() {
		t.Fatal("disabled configuration rejected")
	}
}

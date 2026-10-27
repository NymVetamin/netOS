package config

import "testing"

func TestManagementRuleRequiresEveryAccessCondition(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config, *FirewallRule)
		want   bool
	}{
		{"ssh", func(c *Config, r *FirewallRule) {}, true},
		{"panel range", func(c *Config, r *FirewallRule) { r.DstPort = "8000-9000" }, true},
		{"custom panel", func(c *Config, r *FirewallRule) { c.System.Panel.Port = 9443; r.DstPort = "9443" }, true},
		{"unrestricted tcp", func(c *Config, r *FirewallRule) { r.DstPort = "" }, true},
		{"any protocol", func(c *Config, r *FirewallRule) { r.Protocol = "any" }, true},
		{"disabled", func(c *Config, r *FirewallRule) { r.Enabled = false }, false},
		{"drop", func(c *Config, r *FirewallRule) { r.Action = "drop" }, false},
		{"forward", func(c *Config, r *FirewallRule) { r.Flow = "forward" }, false},
		{"established", func(c *Config, r *FirewallRule) { r.ConnState = "new,established" }, false},
		{"loopback", func(c *Config, r *FirewallRule) { r.Interface = "lo" }, false},
		{"udp ssh", func(c *Config, r *FirewallRule) { r.Protocol = "udp" }, false},
		{"icmp", func(c *Config, r *FirewallRule) { r.Protocol = "icmp" }, false},
		{"other port", func(c *Config, r *FirewallRule) { r.DstPort = "53" }, false},
		{"invalid port", func(c *Config, r *FirewallRule) { r.DstPort = "bad" }, false},
		{"empty source set", func(c *Config, r *FirewallRule) { r.SrcIPSet = "empty" }, false},
		{"missing destination set", func(c *Config, r *FirewallRule) { r.DstIPSet = "missing" }, false},
		{"both nonempty sets", func(c *Config, r *FirewallRule) { r.SrcIPSet = "yes"; r.DstIPSet = "yes" }, true},
		{"duplicate set any nonempty", func(c *Config, r *FirewallRule) {
			c.Firewall.IPSets = append(c.Firewall.IPSets, FirewallIPSet{ID: "yes"})
			r.SrcIPSet = "yes"
		}, true},
		{"empty zone", func(c *Config, r *FirewallRule) { r.Zone = "lan" }, false},
		{"enabled LAN", func(c *Config, r *FirewallRule) { r.Zone = "lan"; c.Networks = []Network{{Enabled: true, Zone: "lan"}} }, true},
		{"disabled LAN", func(c *Config, r *FirewallRule) { r.Zone = "lan"; c.Networks = []Network{{Zone: "lan"}} }, false},
		{"WAN", func(c *Config, r *FirewallRule) { r.Zone = "wan"; c.WANs = []WAN{{Enabled: true}} }, true},
		{"direct channel is not VPN", func(c *Config, r *FirewallRule) {
			r.Zone = "vpn"
			c.Channels = []Channel{{Enabled: true, Type: "direct"}}
		}, false},
		{"VPN channel", func(c *Config, r *FirewallRule) {
			r.Zone = "vpn"
			c.Channels = []Channel{{Enabled: true, Type: "xray"}}
		}, true},
		{"VPN server", func(c *Config, r *FirewallRule) { r.Zone = "vpn"; c.VPNServers = []VPNServer{{Enabled: true}} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.Firewall.IPSets = []FirewallIPSet{{ID: "empty"}, {ID: "yes", Entries: []string{"192.0.2.1"}}}
			r := FirewallRule{Enabled: true, Action: "accept", Flow: "in", Zone: "global", Protocol: "tcp", DstPort: "22", ConnState: "new"}
			tc.change(c, &r)
			if got := c.ruleGrantsManagement(r); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestManagementRuleUsesCurrentConfig(t *testing.T) {
	c := Default()
	c.System.Panel.Port = 9443
	r := FirewallRule{Enabled: true, Action: "accept", Flow: "in", Zone: "vpn", Protocol: "tcp", DstPort: "9443", SrcIPSet: "allowed"}
	c.VPNServers = []VPNServer{{Enabled: true}}
	c.Firewall.IPSets = []FirewallIPSet{{ID: "allowed", Entries: []string{"192.0.2.1"}}}
	check := func(want bool) {
		t.Helper()
		if got := c.ruleGrantsManagement(r); got != want {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	check(true)
	c.Firewall.IPSets[0].Entries = nil
	check(false)
	c.Firewall.IPSets[0].Entries = []string{"192.0.2.2"}
	check(true)
	c.VPNServers[0].Enabled = false
	check(false)
	c.VPNServers[0].Enabled = true
	check(true)
	c.System.Panel.Port = 8443
	check(false)
	c.System.Panel.Port = 9443
	check(true)
}

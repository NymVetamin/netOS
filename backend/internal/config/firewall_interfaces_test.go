package config

import "testing"

func TestFirewallMembershipTracksConfigurationChanges(t *testing.T) {
	c := Default()
	c.Interfaces = []Interface{{ID: "port", Name: "eth1"}, {ID: "port", Name: "duplicate"}}
	c.Networks = []Network{{ID: "lan", Interface: "port", Zone: "lan"}}
	c.Firewall.Rules = []FirewallRule{
		{ID: "a", Flow: "forward", DstZone: "lan", OutInterface: "eth1", Action: "accept"},
		{ID: "b", Flow: "forward", DstZone: "lan", OutInterface: "eth1", Action: "accept"},
	}
	check := func(wantError bool) {
		t.Helper()
		for _, path := range []string{"firewall.rules[0].out_interface", "firewall.rules[1].out_interface"} {
			if got := hasRemainingProblem(c, path, "error"); got != wantError {
				t.Fatalf("%s: error=%t, want %t", path, got, wantError)
			}
		}
	}
	check(false) // Disabled objects still own their saved firewall rules.
	if c.FirewallInterfaceInZone("duplicate", "lan") {
		t.Fatal("duplicate interface ID must not override the first entry")
	}
	c.Interfaces[0].Name = "renamed"
	check(true)
	c.Interfaces[0].Name = "eth1"
	check(false)
	c.Networks[0].Interface = "missing"
	check(true)
	if !c.FirewallInterfaceInZone("", "lan") {
		t.Fatal("unresolved interface name semantics changed")
	}
	c.Networks[0].Interface = "port"
	check(false)
	c.Networks[0].Zone = "wan"
	check(true)
	c.Networks[0].Zone = "lan"
	check(false)
}

func TestFirewallMembershipVirtualInterfaces(t *testing.T) {
	for _, tc := range []struct{ kind, channel, server string }{
		{"wireguard", "wg-ch2", "wg-srv2"},
		{"l2tp", "ppp-ch2", L2TPInterfacePrefix(2) + "+"},
		{"ikev2", "xfrm-ch2", "xfrm-srv2"},
		{"xray", "tun-ch2", ""},
		{"openconnect", "tun-ch2", ""},
		{"ocserv", "", "vpns2+"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			c := Default()
			c.Channels = []Channel{{Type: tc.kind, Index: 2}}
			c.VPNServers = []VPNServer{{Type: tc.kind, Index: 2}}
			for _, name := range []string{tc.channel, tc.server} {
				if name != "" && (!c.FirewallInterfaceInZone(name, "vpn") || c.FirewallInterfaceInZone(name, "lan")) {
					t.Fatalf("wrong zone membership for %s", name)
				}
			}
		})
	}
	for _, proto := range []string{"dhcp", "static", "pppoe", "l2tp"} {
		c := Default()
		c.Interfaces = []Interface{{ID: "port", Name: "eth1"}}
		c.WANs = []WAN{{ID: "uplink", Interface: "port", Proto: proto}}
		ppp := proto == "pppoe" || proto == "l2tp"
		if c.FirewallInterfaceInZone("ppp-uplink", "wan") != ppp || c.FirewallInterfaceInZone("eth1", "wan") == ppp {
			t.Fatalf("wrong WAN interface for %s", proto)
		}
	}
}

func TestForwardOutputValidation(t *testing.T) {
	c := Default()
	c.Interfaces = []Interface{{ID: "a", Name: "br1", Enabled: true}}
	c.Networks = []Network{{ID: "a", Interface: "a", Zone: "lan", Enabled: true, RouterAddress: "192.168.20.1/24"}}
	c.Firewall.Rules = []FirewallRule{{ID: "qa", Name: "qa", Enabled: true, Zone: "global", Flow: "forward", DstZone: "lan", OutInterface: "br1", Action: "accept"}}
	if hasRemainingProblem(c, "firewall.rules[0].out_interface", "error") {
		t.Fatal("valid output rejected")
	}
	c.Firewall.Rules[0].OutInterface = "wrong"
	if !hasRemainingProblem(c, "firewall.rules[0].out_interface", "error") {
		t.Fatal("wrong zone accepted")
	}
	c.Firewall.Rules[0].OutInterface = "br1"
	c.Firewall.Rules[0].DstZone = ""
	c.Firewall.Rules[0].Flow = "in"
	if !hasRemainingProblem(c, "firewall.rules[0].out_interface", "error") {
		t.Fatal("output on input accepted")
	}
	c.VPNServers = []VPNServer{{Type: "ocserv", Index: 2}}
	if !c.FirewallInterfaceInZone("vpns2+", "vpn") {
		t.Fatal("ocserv wildcard not recognized")
	}
}

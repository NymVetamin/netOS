package config

import "testing"

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

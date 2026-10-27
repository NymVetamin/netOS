package config

import (
	"fmt"
	"testing"
)

func TestL2TPPeerInterfacesAreStableAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, index := range []int{1, 10, 9999} {
		for i := 1; i < 256; i++ {
			name := L2TPPeerInterface(index, fmt.Sprintf("10.99.0.%d", i))
			if len(name) > 15 || name == "" || seen[name] {
				t.Fatalf("invalid or duplicate interface %q", name)
			}
			seen[name] = true
		}
	}
	for _, invalid := range []string{"", "not-an-ip", "::1", "10.0.0.1/24"} {
		if got := L2TPPeerInterface(1, invalid); got != "" {
			t.Fatalf("accepted %q: %s", invalid, got)
		}
	}
}

func TestL2TPInterfaceMigrationPreservesSavedRules(t *testing.T) {
	c := Default()
	c.VPNServers = []VPNServer{{Type: "l2tp", Index: 2}}
	c.Firewall.Rules = []FirewallRule{{Interface: "ppp-srv2", OutInterface: "ppp-srv2"}, {Interface: "ppp-ch2"}, {Interface: "wg-srv2"}}
	c.Firewall.NAT = []NATRule{{Interface: "ppp-srv2"}}
	for i := 0; i < 2; i++ {
		c.Normalize()
		if c.Firewall.Rules[0].Interface != "pp2-+" || c.Firewall.Rules[0].OutInterface != "pp2-+" || c.Firewall.NAT[0].Interface != "pp2-+" || c.Firewall.Rules[1].Interface != "ppp-ch2" || c.Firewall.Rules[2].Interface != "wg-srv2" {
			t.Fatalf("invalid migration: %+v", c.Firewall)
		}
	}
}

func TestL2TPMultipleUsersAndDuplicateLogin(t *testing.T) {
	c := Default()
	c.Components = append(c.Components, Component{ID: "l2tp", Installed: true})
	s := VPNServer{ID: "l2tp", Index: 1, Name: "L2TP", Type: "l2tp", Enabled: true, Subnet: "10.99.0.1/24", Port: 1701, DefaultChannel: "direct", Config: map[string]any{"listen": "10.0.0.1"}}
	for i := 2; i < 102; i++ {
		login := fmt.Sprintf("user%d", i)
		s.Peers = append(s.Peers, VPNPeer{ID: login, Name: login, Enabled: true, Address: fmt.Sprintf("10.99.0.%d", i), Credentials: map[string]string{"username": login, "password": "test-secret"}})
	}
	c.VPNServers = []VPNServer{s}
	if r := c.Validate(); r.HasErrors() {
		t.Fatalf("100 valid users rejected: %+v", r.Problems)
	}
	c.VPNServers[0].Peers[1].Credentials["username"] = "user2"
	if r := c.Validate(); !hasErrorAt(r, "vpn_servers[0].peers[1].credentials.username") {
		t.Fatalf("duplicate accepted: %+v", r.Problems)
	}
	c.VPNServers[0].Peers[1].Enabled = false
	if r := c.Validate(); r.HasErrors() {
		t.Fatalf("disabled duplicate rejected: %+v", r.Problems)
	}
}

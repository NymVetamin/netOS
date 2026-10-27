package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSambaSelectionValidationTransitions(t *testing.T) {
	c := Default()
	c.Samba.Networks = []string{"lan"}
	c.Samba.VPNs = []string{"vpn"}
	check := func(lanErrors, vpnErrors int) {
		t.Helper()
		before, _ := json.Marshal(c)
		var r ValidationResult
		c.validateSamba(&r)
		lan, vpn := 0, 0
		for _, p := range r.Problems {
			switch p.Path {
			case "samba.networks":
				lan++
			case "samba.vpns":
				vpn++
			default:
				t.Fatalf("unexpected problem: %+v", p)
			}
		}
		if lan != lanErrors || vpn != vpnErrors {
			t.Fatalf("LAN/VPN errors %d/%d want %d/%d: %+v", lan, vpn, lanErrors, vpnErrors, r.Problems)
		}
		after, _ := json.Marshal(c)
		if !bytes.Equal(before, after) {
			t.Fatal("validation mutated config")
		}
	}
	check(1, 1)
	c.Networks = []Network{{ID: "lan", Enabled: true, Zone: "lan"}}
	c.VPNServers = []VPNServer{{ID: "vpn", Enabled: true, Type: "wireguard"}}
	check(0, 0)
	c.Networks[0].Enabled = false
	c.VPNServers[0].Enabled = false
	check(1, 1)
	c.Networks[0].Enabled = true
	c.VPNServers[0].Enabled = true
	check(0, 0)
	c.Networks[0].Isolated = true
	c.VPNServers[0].Type = "xray"
	check(1, 1)
	c.Networks[0].Isolated = false
	c.Networks[0].Zone = "wan"
	c.VPNServers[0].Type = "ikev2"
	check(1, 0)
	c.Networks[0].Zone = "custom"
	check(0, 0)
	c.Networks = append(c.Networks, Network{ID: "lan"})
	c.VPNServers = append(c.VPNServers, VPNServer{ID: "vpn", Enabled: true, Type: "xray"})
	check(0, 0)
	c.Networks[0], c.Networks[1] = c.Networks[1], c.Networks[0]
	c.VPNServers[0], c.VPNServers[1] = c.VPNServers[1], c.VPNServers[0]
	check(0, 0)
	c.Samba.Networks = append(c.Samba.Networks, "lan", "missing")
	c.Samba.VPNs = append(c.Samba.VPNs, "vpn", "missing")
	check(2, 2)
	c.Samba.Networks = c.Samba.Networks[:1]
	c.Samba.VPNs = c.Samba.VPNs[:1]
	check(0, 0)
	c.Samba.Networks = nil
	c.Samba.VPNs = nil
	check(0, 0)
}

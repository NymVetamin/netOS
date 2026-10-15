package config

import "testing"

func TestRuntimeNetworkSuspendsWithoutLosingDesiredSettings(t *testing.T) {
	c := Default()
	c.Interfaces = []Interface{{ID: "p", Name: "eth0", Type: "physical", Enabled: false}, {ID: "v", Name: "vlan7", Type: "vlan", Parent: "p", Enabled: true}, {ID: "b", Name: "br0", Type: "bridge", Members: []string{"p"}, Enabled: true}}
	c.WANs = []WAN{{ID: "w", Interface: "v", Enabled: true, Proto: "pppoe", Username: "retained", Password: "retained"}}
	r := c.RuntimeNetworkConfig()
	if r.Interfaces[1].Enabled || r.WANs[0].Enabled {
		t.Fatal("disabled parent bypassed")
	}
	if !r.Interfaces[2].Enabled {
		t.Fatal("bridge should retain its independent switch")
	}
	if !c.Interfaces[1].Enabled || !c.WANs[0].Enabled || r.WANs[0].Password != "retained" {
		t.Fatal("desired configuration lost")
	}
	c.Interfaces[0].Enabled = true
	if !c.RuntimeNetworkConfig().WANs[0].Enabled {
		t.Fatal("uplink not resumed")
	}
	c.Interfaces[0].Enabled = false
	if c.RuntimeNetworkConfig().WANs[0].Enabled {
		t.Fatal("repeat disable failed")
	}
}

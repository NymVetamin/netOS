package config

import "testing"

func TestRuntimeSnapshotMatchesIndividualResolution(t *testing.T) {
	c := &Config{Interfaces: []Interface{
		{ID: "tail", Type: "vlan", Parent: "a", Enabled: true},
		{ID: "a", Type: "vlan", Parent: "b", Enabled: true},
		{ID: "b", Type: "vlan", Parent: "a", Enabled: true},
		{ID: "a", Enabled: true}, // The earlier VLAN wins.
		{ID: "missing-parent", Type: "vlan", Parent: "gone", Enabled: true},
		{ID: "no-parent", Type: "vlan", Enabled: true},
	}, WANs: []WAN{{Interface: "tail", Enabled: true}, {Interface: "gone", Enabled: true}, {Interface: "a"}}}
	for _, parent := range []string{"a", "no-parent", "gone", "a"} {
		c.Interfaces[2].Parent = parent
		snapshot := c.RuntimeNetworkConfig()
		for i, iface := range c.Interfaces {
			if snapshot.Interfaces[i].ID != iface.ID || snapshot.Interfaces[i].Enabled != c.InterfaceEnabled(iface.ID) {
				t.Fatalf("parent %q: interface %d differs", parent, i)
			}
		}
		for i, wan := range c.WANs {
			_, known := c.InterfaceByID(wan.Interface)
			if snapshot.WANs[i].Enabled != (wan.Enabled && (!known || c.InterfaceEnabled(wan.Interface))) {
				t.Fatalf("parent %q: WAN %d differs", parent, i)
			}
		}
	}
	if (*Config)(nil).RuntimeNetworkConfig() != nil || (&Config{}).RuntimeNetworkConfig().Interfaces != nil {
		t.Fatal("empty snapshot changed")
	}
}

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

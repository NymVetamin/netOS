package config

import (
	"fmt"
	"reflect"
	"testing"
)

func peerExitFixture() *Config {
	c := Default()
	c.VPNServers = []VPNServer{{ID: "server", Index: 4, Type: "wireguard", Enabled: true, Subnet: "10.7.0.1/24", Peers: []VPNPeer{{ID: "vps", Name: "VPS", Enabled: true, UseAsChannel: true}}}}
	return c
}

func TestAmneziaWGPeerChannelLifecycle(t *testing.T) {
	c := peerExitFixture()
	c.VPNServers[0].Type = "amneziawg"
	c.Normalize()
	ch := c.Channels[len(c.Channels)-1]
	if ch.Type != "amneziawg" || ch.WireGuardPeer.ServerIndex != 4 {
		t.Fatal("wrong shared channel protocol")
	}
	r := &ValidationResult{}
	c.validateWireGuardPeerChannels(r)
	if r.HasErrors() {
		t.Fatal(r.Problems)
	}
	c.Firewall.NAT = append(c.Firewall.NAT, NATRule{ID: "channel-nat-" + ch.ID, System: true, Interface: "awg-srv4"})
	c.VPNServers[0].Type = "wireguard"
	c.Normalize()
	if c.Channels[len(c.Channels)-1].Type != "wireguard" || c.Firewall.NAT[len(c.Firewall.NAT)-1].Interface != "wg-srv4" {
		t.Fatal("protocol switch left stale interface")
	}
	c.VPNServers[0].Peers = nil
	c.Normalize()
	if len(c.Channels) != 1 {
		t.Fatal("deleted exit retained channel")
	}
}

func TestWireGuardPeerChannelLifecycle(t *testing.T) {
	c := peerExitFixture()
	c.Normalize()
	id := WireGuardPeerChannelID("server")
	ch := &c.Channels[len(c.Channels)-1]
	if ch.ID != id || ch.WireGuardPeer.ServerIndex != 4 || !ch.Enabled || ch.FailMode != "block" {
		t.Fatal(ch)
	}
	ch.Name = "Europe"
	ch.Probe.Interval = 23
	ch.Enabled = false
	before := append([]Channel(nil), c.Channels...)
	c.Normalize()
	if !reflect.DeepEqual(before, c.Channels) {
		t.Fatal("repeat lost user settings")
	}
	r := &ValidationResult{}
	c.validateWireGuardPeerChannels(r)
	if r.HasErrors() {
		t.Fatal(r)
	}
	profile, err := c.VPNServers[0].WireGuardProfileFor(c.VPNServers[0].Peers[0])
	if err != nil {
		t.Fatal(err)
	}
	if profile.UseRouterDNS || len(profile.DNS) != 0 || !reflect.DeepEqual(profile.AllowedIPs, []string{"10.7.0.1/32"}) {
		t.Fatal(profile)
	}
	c.Firewall.NAT = append(c.Firewall.NAT, NATRule{ID: "channel-nat-" + id, System: true, Interface: "wg-srv4"})
	c.VPNServers[0].Peers[0].UseAsChannel = false
	c.Normalize()
	for _, rule := range c.Firewall.NAT {
		if rule.ID == "channel-nat-"+id {
			t.Fatal("stale shared-interface NAT")
		}
	}
	for _, ch := range c.Channels {
		if ch.ID == id {
			t.Fatal("exit was not removed")
		}
	}
}

func TestWireGuardPeerChannelRejectsInvalidSources(t *testing.T) {
	cases := map[string]func(*Config){
		"two exits": func(c *Config) {
			c.VPNServers[0].Peers = append(c.VPNServers[0].Peers, VPNPeer{ID: "other", UseAsChannel: true, Enabled: true})
		},
		"disabled peer":   func(c *Config) { c.VPNServers[0].Peers[0].Enabled = false },
		"disabled server": func(c *Config) { c.VPNServers[0].Enabled = false },
		"self exit":       func(c *Config) { c.VPNServers[0].Peers[0].Channel = WireGuardPeerChannelID("server") },
		"wrong index":     func(c *Config) { c.Channels[len(c.Channels)-1].WireGuardPeer.ServerIndex = 8 },
		"own credentials": func(c *Config) { c.Channels[len(c.Channels)-1].Config = map[string]any{"private_key": "secret"} },
		"non WG":          func(c *Config) { c.VPNServers[0].Type = "xray" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := peerExitFixture()
			c.Normalize()
			change(c)
			r := &ValidationResult{}
			c.validateWireGuardPeerChannels(r)
			if !r.HasErrors() {
				t.Fatal("accepted invalid exit")
			}
		})
	}
}

func BenchmarkWireGuardPeerChannels(b *testing.B) {
	for _, n := range []int{25, 2500} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := Default()
			c.VPNServers = nil
			for i := 0; i < n; i++ {
				c.VPNServers = append(c.VPNServers, VPNServer{ID: fmt.Sprintf("s%d", i), Index: i + 1, Type: "wireguard", Enabled: true, Peers: []VPNPeer{{ID: "exit", Name: "Exit", Enabled: true, UseAsChannel: true}}})
			}
			c.normalizeWireGuardPeerChannels()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.normalizeWireGuardPeerChannels()
				r := &ValidationResult{}
				c.validateWireGuardPeerChannels(r)
				if r.HasErrors() {
					b.Fatal(r)
				}
			}
		})
	}
}

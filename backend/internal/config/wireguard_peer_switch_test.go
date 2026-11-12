package config

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPeerSwitchPreservesNameLookupContracts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		servers       []VPNServer
		oldName, want string
	}{
		{"first matching peer", []VPNServer{{ID: "s", Type: "xray", Peers: []VPNPeer{{ID: "old", Name: "first"}, {ID: "old", Name: "second"}}}}, "first", "new"},
		{"later duplicate server", []VPNServer{{ID: "s", Peers: []VPNPeer{{ID: "other"}}}, {ID: "s", Peers: []VPNPeer{{ID: "old", Name: "later"}}}}, "later", "new"},
		{"missing empty", nil, "", "new"},
		{"missing manual", nil, "manual", "manual"},
		{"manual", []VPNServer{{ID: "s", Peers: []VPNPeer{{ID: "old", Name: "auto"}}}}, "custom", "custom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{VPNServers: append(tc.servers, VPNServer{ID: "s", Type: "wireguard", Index: 7, Peers: []VPNPeer{{ID: "next", Name: "new", UseAsChannel: true}}}), Channels: []Channel{{ID: WireGuardPeerChannelID("s"), Index: 9, Name: tc.oldName, Type: "wireguard", Mode: "tun", Enabled: false, FailMode: "block", Probe: Probe{Interval: 23}, WireGuardPeer: &WireGuardPeerChannel{ServerID: "s", PeerID: "old", ServerIndex: 4}}}}
			c.Firewall.NAT = []NATRule{{ID: "channel-nat-wg-exit-s", System: true, Interface: "wg-srv4"}, {ID: "manual", Interface: "wg-srv4"}}
			// Exercise the indexed path after a separate first switch.
			c.VPNServers = append(c.VPNServers, VPNServer{ID: "prefix", Type: "wireguard", Index: 1, Peers: []VPNPeer{{ID: "b", Name: "Prefix", UseAsChannel: true}}})
			c.Channels = append([]Channel{{ID: WireGuardPeerChannelID("prefix"), Index: 1, WireGuardPeer: &WireGuardPeerChannel{ServerID: "prefix", PeerID: "a"}}}, c.Channels...)
			c.normalizeWireGuardPeerChannels()
			ch := c.Channels[1]
			if len(c.Channels) != 2 || ch.Name != tc.want || ch.Index != 9 || ch.Enabled || ch.Probe.Interval != 23 || ch.FailMode != "block" || ch.WireGuardPeer.PeerID != "next" {
				t.Fatalf("lost properties: %+v", ch)
			}
			if c.Firewall.NAT[0].Interface != "wg-srv7" || c.Firewall.NAT[1].Interface != "wg-srv4" {
				t.Fatal("NAT ownership changed")
			}
			before := append([]Channel(nil), c.Channels...)
			c.normalizeWireGuardPeerChannels()
			if !reflect.DeepEqual(before, c.Channels) {
				t.Fatal("repeat changed channels")
			}
		})
	}
}

func BenchmarkPeerExitSwitchNormalization(b *testing.B) {
	for _, n := range []int{25, 2500} {
		for _, change := range []string{"none", "one", "all"} {
			b.Run(fmt.Sprintf("%d/switch=%v", n, change), func(b *testing.B) {
				c := Default()
				c.VPNServers = nil
				for i := 0; i < n; i++ {
					c.VPNServers = append(c.VPNServers, VPNServer{ID: fmt.Sprintf("s%d", i), Index: i + 1, Type: "wireguard", Enabled: true, Peers: []VPNPeer{{ID: "a", Name: "First", Enabled: true, UseAsChannel: true}, {ID: "b", Name: "Second", Enabled: true}}})
				}
				c.Normalize()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if change != "none" {
						for si := range c.VPNServers {
							if change == "one" && si != n-1 {
								continue
							}
							p := c.VPNServers[si].Peers
							p[0].UseAsChannel = !p[0].UseAsChannel
							p[1].UseAsChannel = !p[1].UseAsChannel
						}
					}
					c.Normalize()
					if len(c.Channels) != n+1 {
						b.Fatal("channel count changed")
					}
					want := "First"
					if c.VPNServers[n-1].Peers[1].UseAsChannel {
						want = "Second"
					}
					if c.Channels[len(c.Channels)-1].Name != want {
						b.Fatal("name did not follow exit")
					}
				}
			})
		}
	}
}

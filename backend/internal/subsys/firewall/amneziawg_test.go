package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestAmneziaWGKeepsWireGuardFirewallPolicy(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "wan0", Name: "eth0", Type: "physical", Enabled: true}}
	c.WANs = []config.WAN{{ID: "wan", Index: 1, Interface: "wan0", Enabled: true, Proto: "dhcp"}}
	c.Channels = append(c.Channels, config.Channel{ID: "vpn", Index: 4, Enabled: true, Type: "wireguard"})
	c.VPNServers = []config.VPNServer{{ID: "server", Index: 3, Enabled: true, Type: "wireguard", Port: 51823, Subnet: "10.23.0.1/24", DefaultChannel: "direct", Peers: []config.VPNPeer{{ID: "peer", Enabled: true, Address: "10.23.0.2", Channel: "vpn"}}}}
	wg, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Channels[1].Type = "amneziawg"
	c.VPNServers[0].Type = "amneziawg"
	awg, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	replace := strings.NewReplacer("wg-ch4", "awg-ch4", "wg-srv3", "awg-srv3")
	if replace.Replace(wg.IPv4) != awg.IPv4 || replace.Replace(wg.IPv6) != awg.IPv6 {
		t.Fatal("AWG firewall policy differs beyond owned interface names")
	}
	for _, want := range []string{"-p udp --dport 51823", "-i awg-srv3 -s 10.23.0.2/32", "--set-mark 0x1004", "-o awg-ch4"} {
		if !strings.Contains(awg.IPv4, want) {
			t.Fatalf("missing %s", want)
		}
	}
}

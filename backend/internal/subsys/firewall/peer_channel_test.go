package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestWireGuardPeerChannelFirewall(t *testing.T) {
	c := config.Default()
	c.VPNServers = []config.VPNServer{{ID: "s", Index: 4, Type: "wireguard", Enabled: true, Peers: []config.VPNPeer{{ID: "exit", Address: "10.7.0.2", Enabled: true, UseAsChannel: true}, {ID: "phone", Address: "10.7.0.3", Enabled: true}}}}
	c.Normalize()
	ch := c.Channels[len(c.Channels)-1]
	check := func(wantNAT bool) {
		t.Helper()
		rules, err := Build(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"-A PREROUTING -i wg-srv4 -j NETOS-WGEXIT4", "--ctdir REPLY --ctstate ESTABLISHED,RELATED -j RETURN", "-A NETOS-WGEXIT4 -s 10.7.0.2/31 -j RETURN", "-A NETOS-WGEXIT4 -j DROP"} {
			if !strings.Contains(rules.IPv4, want) {
				t.Fatal(want)
			}
		}
		if strings.Contains(rules.IPv4, "-A INPUT -i wg-srv4 -m conntrack --ctdir ORIGINAL -j CONNMARK") {
			t.Fatal("ordinary client replies must not follow exit failover")
		}
		found := false
		for _, line := range strings.Split(rules.IPv4, "\n") {
			if strings.HasPrefix(line, "-A POSTROUTING -o wg-srv4 ") {
				found = true
				if !strings.Contains(line, "-m connmark --mark ") || !strings.Contains(line, "--ctdir ORIGINAL") {
					t.Fatal("unscoped NAT", line)
				}
			}
		}
		if found != wantNAT {
			t.Fatalf("NAT present %v wanted %v", found, wantNAT)
		}
	}
	check(true)
	c.Firewall.NAT = []config.NATRule{{ID: "channel-nat-" + ch.ID, System: true, Direction: "source", Interface: "wg-srv4", Enabled: false}}
	check(false)
	c.Firewall.NAT[0].Enabled = true
	check(true)
}

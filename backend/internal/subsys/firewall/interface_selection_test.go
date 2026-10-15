package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestForwardExactOutputDoesNotExpandWholeZone(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "a", Name: "br-lan", Enabled: true}, {ID: "b", Name: "br1", Enabled: true}}
	c.Networks = []config.Network{{ID: "a", Interface: "a", Enabled: true, Zone: "lan", RouterAddress: "192.168.10.1/24"}, {ID: "b", Interface: "b", Enabled: true, Zone: "lan", RouterAddress: "192.168.20.1/24"}}
	for _, zone := range []string{"global", "lan"} {
		for _, out := range []string{"", "br1", "wrong"} {
			c.Firewall.Rules = []config.FirewallRule{{ID: "qa", Name: "qa-exact", Enabled: true, Zone: zone, Flow: "forward", DstZone: "lan", Interface: "br-lan", OutInterface: out, DstIP: "192.168.20.0/24", Action: "accept"}}
			r, _ := Build(c)
			count := 0
			for _, line := range strings.Split(r.IPv4, "\n") {
				if !strings.Contains(line, "qa-exact") {
					continue
				}
				count++
				if strings.Count(line, " -o ") != 1 || strings.Count(line, " -i ") != 1 {
					t.Fatal(line)
				}
				if out != "" && !strings.Contains(line, " -o br1 ") {
					t.Fatal(line)
				}
			}
			want := 1
			if out == "" {
				want = 2
			}
			if out == "wrong" {
				want = 0
			}
			if count != want {
				t.Fatalf("%s/%s: %d != %d", zone, out, count, want)
			}
		}
	}
	c.Firewall.Rules = []config.FirewallRule{{Name: "qa-output", Enabled: true, Zone: "global", Flow: "out", Interface: "br1", Action: "accept"}}
	r, _ := Build(c)
	if !strings.Contains(r.IPv4, "-A OUTPUT -o br1") {
		t.Fatal("legacy output changed")
	}
	c.Firewall.Rules[0] = config.FirewallRule{Name: "qa-global", Enabled: true, Zone: "global", Flow: "forward", Interface: "br-lan", OutInterface: "br1", Action: "accept"}
	r, _ = Build(c)
	if !strings.Contains(r.IPv4, "-A FORWARD -o br1 -i br-lan") {
		t.Fatal("explicit output without destination zone lost")
	}
}

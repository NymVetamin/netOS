package api

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func natMergeFixture(n int, fresh bool) (*config.Config, *config.Config) {
	previous := natProjectionFixture(n)
	previous.Firewall.NAT = nil
	incoming := *previous
	for _, wan := range previous.WANs {
		r := config.NATRule{ID: "wan-nat-" + wan.ID, Name: fmt.Sprintf("NAT аплинка «%s»", wan.Name), System: true, Enabled: true, Direction: "source", Interface: wanDevice(previous, wan)}
		incoming.Firewall.NAT = append(incoming.Firewall.NAT, r)
	}
	if !fresh {
		previous.Firewall.NAT = append([]config.NATRule(nil), incoming.Firewall.NAT...)
	}
	return previous, &incoming
}

func TestNetworkNATMergeEquivalent(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		for variant := 0; variant < 18; variant++ {
			previous, incoming := natMergeFixture(4, fresh)
			visible := *previous
			visible.Firewall.NAT = append([]config.NATRule(nil), previous.Firewall.NAT...)
			switch variant {
			case 1:
				incoming.Firewall.NAT[0].Enabled = false
			case 2:
				incoming.Firewall.NAT[0].Name = "changed"
			case 3:
				incoming.Firewall.NAT = append(incoming.Firewall.NAT, incoming.Firewall.NAT[0])
			case 4:
				incoming.Firewall.NAT = incoming.Firewall.NAT[1:]
			case 5:
				previous.Firewall.NAT = append(previous.Firewall.NAT, incoming.Firewall.NAT[0])
				incoming.Firewall.NAT[0].Enabled = false
			case 6:
				previous.Firewall.NAT = append(previous.Firewall.NAT, config.NATRule{ID: "hidden", Interface: "p0"})
			case 7:
				visible.Firewall.NAT = append(visible.Firewall.NAT, config.NATRule{ID: "manual", Interface: "p0"})
				incoming.Firewall.NAT = append(incoming.Firewall.NAT, visible.Firewall.NAT[len(visible.Firewall.NAT)-1])
				incoming.Firewall.NAT[0].Enabled = false
			case 8:
				incoming.WANs = append([]config.WAN{{ID: "p0", Interface: "p1", Name: "duplicate"}}, incoming.WANs...)
			case 9:
				incoming.Interfaces = append([]config.Interface{{ID: "p0", Name: ""}}, incoming.Interfaces...)
			case 10:
				incoming.Firewall.NAT[0].Comment = "extra"
			case 11:
				incoming.Firewall.OutputPolicy = "drop"
			case 12:
				incoming.WANs = append([]config.WAN(nil), incoming.WANs...)
				incoming.WANs[0].Proto = "pppoe"
				incoming.WANs[1].Proto = "l2tp"
				incoming.Firewall.NAT[0].Interface = "ppp-p0"
				incoming.Firewall.NAT[1].Interface = "ppp-p1"
			case 13:
				incoming.WANs = append([]config.WAN(nil), incoming.WANs...)
				incoming.WANs[1].Interface = "p0"
				incoming.Firewall.NAT[1].Interface = "p0"
			case 14:
				previous.Firewall.NAT = append(previous.Firewall.NAT, config.NATRule{ID: incoming.Firewall.NAT[0].ID, Interface: "hidden"})
			case 15:
				visible.Firewall.NAT = append(visible.Firewall.NAT, incoming.Firewall.NAT[0])
			case 16:
				incoming.WANs = nil
			case 17:
				incoming.Firewall.NAT = nil
				previous.Firewall.NAT = nil
				visible.Firewall.NAT = nil
			}
			before := configObject(previous)
			for range 2 {
				want, werr := oldMergeNetworkNAT(previous, &visible, incoming)
				got, gerr := mergeNetworkNAT(previous, &visible, incoming)
				if fmt.Sprint(gerr) != fmt.Sprint(werr) || !reflect.DeepEqual(got, want) {
					t.Fatal("merge differs", fresh, variant, gerr, werr)
				}
				if !reflect.DeepEqual(configObject(previous), before) {
					t.Fatal("mutated previous")
				}
			}
		}
	}
}

func BenchmarkNetworkNATMergeLookup(b *testing.B) {
	for _, n := range []int{16, 512} {
		for _, fresh := range []bool{false, true} {
			b.Run(fmt.Sprintf("%d/new=%t", n, fresh), func(b *testing.B) {
				previous, incoming := natMergeFixture(n, fresh)
				b.ReportAllocs()
				for b.Loop() {
					got, err := mergeNetworkNAT(previous, previous, incoming)
					if err != nil || len(got.NAT) != n {
						b.Fatal(err, len(got.NAT))
					}
				}
			})
		}
	}
}

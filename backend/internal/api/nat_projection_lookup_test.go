package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func oldWANMasquerade(c *config.Config, rule config.NATRule) bool {
	if rule.Direction == "destination" || rule.Source != "" || rule.ToSource != "" || rule.Interface == "" {
		return false
	}
	for _, wan := range c.WANs {
		if wanDevice(c, wan) == rule.Interface {
			return true
		}
	}
	return false
}

func natProjectionFixture(n int) *config.Config {
	c := config.Default()
	for i := range n {
		id := fmt.Sprintf("p%d", i)
		c.Interfaces = append(c.Interfaces, config.Interface{ID: id, Name: id})
		c.WANs = append(c.WANs, config.WAN{ID: id, Interface: id, Proto: "static"})
		c.Firewall.NAT = append(c.Firewall.NAT, config.NATRule{ID: id, Interface: "absent", Direction: "source"})
	}
	return c
}

func TestNATProjectionLookupEquivalent(t *testing.T) {
	c := natProjectionFixture(4)
	c.Interfaces = append([]config.Interface{{ID: "p0", Name: ""}, {ID: "", Name: "empty-id"}}, c.Interfaces...)
	c.WANs = append(c.WANs, config.WAN{ID: "ppp", Proto: "pppoe"}, config.WAN{ID: "l2tp", Proto: "l2tp"}, config.WAN{Interface: "missing"}, config.WAN{Interface: ""})
	for _, name := range []string{"", "changed", "p0"} {
		c.Interfaces[0].Name = name
		c.Firewall.NAT = nil
		for _, iface := range []string{"p0", "p1", "changed", "ppp-ppp", "ppp-l2tp", "empty-id", "absent", ""} {
			for i := range 5 {
				r := config.NATRule{ID: fmt.Sprint(len(c.Firewall.NAT)), Interface: iface, System: i%2 == 0, Enabled: i%2 == 1}
				switch i {
				case 1:
					r.Direction = "destination"
				case 2:
					r.Source = "192.0.2.0/24"
				case 3:
					r.ToSource = "192.0.2.1"
				}
				c.Firewall.NAT = append(c.Firewall.NAT, r)
			}
		}
		var want []config.NATRule
		for _, rule := range c.Firewall.NAT {
			if oldWANMasquerade(c, rule) {
				want = append(want, rule)
			}
		}
		for _, level := range []string{"view", "manage"} {
			for range 2 {
				got, err := scopedConfig(limitedRequest(map[string]string{"network": level}), c)
				if err != nil || !reflect.DeepEqual(got.Firewall.NAT, want) {
					t.Fatal("projection changed", level, err)
				}
			}
		}
	}
}

func TestNATProjectionFingerprint(t *testing.T) {
	for _, n := range []int{16, 512} {
		got, err := scopedConfig(limitedRequest(map[string]string{"network": "view"}), natProjectionFixture(n))
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("n=%d config=%x", n, sha256.Sum256(data))
	}
}

func TestNATProjectionWithoutWAN(t *testing.T) {
	c := natProjectionFixture(16)
	c.WANs = nil
	got, err := scopedConfig(limitedRequest(map[string]string{"network": "view"}), c)
	if err != nil || len(got.Firewall.NAT) != 0 {
		t.Fatal("exposed NAT without an uplink", err)
	}
}

func BenchmarkNATProjectionLookup(b *testing.B) {
	for _, n := range []int{16, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := natProjectionFixture(n)
			r := limitedRequest(map[string]string{"network": "view"})
			b.ReportAllocs()
			for b.Loop() {
				if _, err := scopedConfig(r, c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkNATToggleClassification(b *testing.B) {
	for _, n := range []int{16, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			previous := natProjectionFixture(n)
			for i := range previous.Firewall.NAT {
				previous.Firewall.NAT[i].Interface = previous.Interfaces[i].Name
				previous.Firewall.NAT[i].System = true
				previous.Firewall.NAT[i].Enabled = true
			}
			incoming := *previous
			incoming.Firewall.NAT = append([]config.NATRule(nil), previous.Firewall.NAT...)
			for i := range incoming.Firewall.NAT {
				incoming.Firewall.NAT[i].Enabled = false
			}
			b.ReportAllocs()
			for b.Loop() {
				got, err := mergeNetworkNAT(previous, previous, &incoming)
				if err != nil {
					b.Fatal(err)
				}
				for i, rule := range got.NAT {
					if rule.Enabled || !previous.Firewall.NAT[i].Enabled {
						b.Fatal("toggle result or input changed")
					}
				}
			}
		})
	}
}

package firewall

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func iptvSourcesFixture(n int) *config.Config {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "up", Name: "eth0"}}
	c.WANs = []config.WAN{{ID: "wan", Interface: "up", Enabled: true, Proto: "dhcp"}}
	c.IPTV = config.IPTV{Enabled: true, Upstream: "wan"}
	for i := range n {
		id := fmt.Sprintf("lan%d", i)
		c.Interfaces = append(c.Interfaces, config.Interface{ID: id, Name: id})
		c.Networks = append(c.Networks, config.Network{ID: id, Interface: id, Enabled: true, RouterAddress: fmt.Sprintf("10.%d.0.1/24", i)})
		c.IPTV.Networks = append(c.IPTV.Networks, id)
		c.IPTV.Sources = append(c.IPTV.Sources, fmt.Sprintf("172.16.%d.8/24", n-i-1))
	}
	return c
}

func TestIPTVSourcePreparationEquivalent(t *testing.T) {
	c := iptvSourcesFixture(4)
	c.Networks[1].Interface = "missing"
	c.Networks[2].RouterAddress = "invalid"
	for _, sources := range [][]string{nil, {}, {"bad", "2001:db8::/32"}, {"192.0.2.9/24", "192.0.2.1/24", "198.51.100.0/24"}, {"0.0.0.0/0"}, {"203.0.113.0/24"}} {
		c.IPTV.Sources = sources
		for _, enabled := range []bool{true, false, true} {
			c.IPTV.Enabled = enabled
			for _, policy := range []string{"accept", "drop"} {
				c.Firewall.OutputPolicy = policy
				for range 2 {
					var old, current builder
					old.oldIPTVAccess(c)
					current.iptvAccess(c)
					if old.String() != current.String() {
						t.Fatal("IPTV output changed", sources, enabled, policy)
					}
				}
			}
		}
	}
	c.IPTV.Upstream = "missing"
	var b builder
	b.iptvAccess(c)
	if b.String() != "" {
		t.Fatal("unknown upstream emitted rules")
	}
}

func TestIPTVBuildFingerprint(t *testing.T) {
	for _, n := range []int{8, 128} {
		rules, err := Build(iptvSourcesFixture(n))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("n=%d v4=%x v6=%x", n, sha256.Sum256([]byte(rules.IPv4)), sha256.Sum256([]byte(rules.IPv6)))
	}
}

func BenchmarkIPTVSourcesBuild(b *testing.B) {
	for _, n := range []int{8, 128} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := iptvSourcesFixture(n)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Build(c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

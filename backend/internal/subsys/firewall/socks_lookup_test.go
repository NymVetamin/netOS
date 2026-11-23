package firewall

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func socksLookupFixture(n int) *config.Config {
	c := config.Default()
	c.Interfaces, c.Networks, c.WANs = nil, nil, nil
	c.Socks = config.Socks{Enabled: true, Port: 1080, AllowWAN: true}
	for i := range n {
		id := fmt.Sprintf("port%d", i)
		c.Interfaces = append(c.Interfaces, config.Interface{ID: id, Name: id, Enabled: true})
		c.Networks = append(c.Networks, config.Network{ID: id, Interface: id, Enabled: true, RouterAddress: fmt.Sprintf("10.%d.%d.1/24", i/256, i%256)})
		c.Socks.Networks = append(c.Socks.Networks, id)
		c.WANs = append(c.WANs, config.WAN{ID: id, Interface: id, Enabled: true, Proto: "dhcp"})
	}
	return c
}

func TestSocksInterfaceLookupEquivalent(t *testing.T) {
	c := socksLookupFixture(6)
	c.Interfaces = append([]config.Interface{{ID: "port0", Name: ""}, {ID: "", Name: "empty-id"}}, c.Interfaces...)
	c.Networks[1].Interface = "missing"
	c.Networks[2].Interface = ""
	c.Networks[3].RouterAddress = "invalid"
	c.Networks[4].Enabled = false
	c.Socks.Networks = append(c.Socks.Networks, "port0", "unknown")
	c.WANs[0].Proto, c.WANs[1].Proto = "pppoe", "l2tp"
	c.WANs[2].Interface, c.WANs[3].Interface = "missing", ""
	c.WANs[3].Proto, c.WANs[4].Proto = "static", "unknown"
	c.WANs[5].Enabled = false
	c.VPNServers = []config.VPNServer{{ID: "vpn", Type: "ikev2", Enabled: true, Subnet: "192.0.2.1/24"}}
	c.Socks.VPNs = []string{"vpn"}
	for _, name := range []string{"", "renamed", "again"} {
		c.Interfaces[0].Name = name
		for _, enabled := range []bool{true, false} {
			c.Socks.Enabled = enabled
			for _, wan := range []bool{true, false} {
				c.Socks.AllowWAN = wan
				for _, policy := range []string{"accept", "drop"} {
					c.Firewall.OutputPolicy = policy
					for range 2 {
						var old, current builder
						old.oldSocksAccess(c)
						current.socksAccess(c)
						if old.String() != current.String() {
							t.Fatal("SOCKS rules changed", name, enabled, wan, policy)
						}
					}
				}
			}
		}
	}
}

func TestSocksBuildFingerprint(t *testing.T) {
	for _, n := range []int{16, 512} {
		rules, err := Build(socksLookupFixture(n))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("n=%d v4=%x v6=%x", n, sha256.Sum256([]byte(rules.IPv4)), sha256.Sum256([]byte(rules.IPv6)))
	}
}

func BenchmarkSocksLookupBuild(b *testing.B) {
	for _, n := range []int{16, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := socksLookupFixture(n)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Build(c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

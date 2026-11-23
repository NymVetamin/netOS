package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
)

func gatewayPrefixFixture(n int) *Config {
	c := Default()
	c.Interfaces = []Interface{{ID: "lan", Name: "br0"}, {ID: "lan", Name: "duplicate"}}
	for i := range n {
		c.Networks = append(c.Networks, Network{ID: fmt.Sprint(i), Enabled: true, Interface: "lan", RouterAddress: fmt.Sprintf("10.%d.%d.1/24", i/256, i%256)})
		c.Routing.Static = append(c.Routing.Static, StaticRoute{Enabled: true, Destination: "default", Gateway: fmt.Sprintf("192.0.%d.%d", i/256, i%256), Metric: i})
	}
	return c
}

func TestGatewayPrefixEquivalent(t *testing.T) {
	c := gatewayPrefixFixture(4)
	c.Networks = append(c.Networks, Network{Enabled: true, Interface: "lan", RouterAddress: "invalid"}, Network{Enabled: true, RouterAddress: "2001:db8::1/64"}, Network{Enabled: true, RouterAddress: "::ffff:192.0.2.1/120"})
	c.WANs = []WAN{{Enabled: true, Proto: "static", Interface: "lan", Address: "198.51.100.1/24"}, {Enabled: true, Underlay: "static", Address: "203.0.113.1/24"}, {Enabled: false, Address: "0.0.0.0/0", Proto: "static"}}
	c.VPNServers = []VPNServer{{Enabled: true, Subnet: "172.16.0.1/16"}, {Enabled: false, Subnet: "0.0.0.0/0"}}
	for _, replacement := range []string{"10.0.0.1/24", "10.99.0.1/24", "invalid", "10.0.0.1/24"} {
		c.Networks[0].RouterAddress = replacement
		names := map[string]string{}
		prefixes := map[string]netip.Prefix{}
		var direct directRouteIndex
		for _, iface := range []string{"", "lan", "br0", "duplicate", "missing"} {
			for _, raw := range []string{"10.0.0.2", "10.99.0.2", "198.51.100.2", "203.0.113.2", "172.16.1.1", "2001:db8::2", "2001:db8::2%br0", "::ffff:192.0.2.2", "192.0.2.2"} {
				route, gateway := StaticRoute{Interface: iface}, netip.MustParseAddr(raw)
				for range 2 {
					var oldDirect directRouteIndex
					want := c.oldStaticGatewayConnected(route, gateway, map[string]string{}, &oldDirect)
					if got := c.staticGatewayConnected(route, gateway, names, prefixes, &direct); got != want {
						t.Fatal(replacement, iface, raw, got, want)
					}
				}
			}
		}
	}
}

func TestGatewayPrefixValidationFingerprint(t *testing.T) {
	for _, n := range []int{16, 256} {
		data, err := json.Marshal(gatewayPrefixFixture(n).Validate())
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("n=%d result=%x", n, sha256.Sum256(data))
	}
}

func TestGatewayPrefixValidationRefreshesSources(t *testing.T) {
	c := gatewayPrefixFixture(1)
	c.Routing.Static[0].Gateway = "10.0.0.2"
	for _, tc := range []struct {
		address string
		warning bool
	}{
		{"10.0.0.1/24", false}, {"10.99.0.1/24", true}, {"invalid", true}, {"10.0.0.1/24", false},
	} {
		c.Networks[0].RouterAddress = tc.address
		for range 2 {
			r := c.Validate()
			p, found := problemAt(r, "routing.static[0].gateway")
			if found != tc.warning || (found && p.Severity != "warning") {
				t.Fatal(tc, r.Problems)
			}
		}
	}
}

func BenchmarkGatewayPrefixValidation(b *testing.B) {
	for _, n := range []int{16, 256} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := gatewayPrefixFixture(n)
			b.ReportAllocs()
			for b.Loop() {
				c.Validate()
			}
		})
	}
}

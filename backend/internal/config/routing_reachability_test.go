package config

import (
	"net/netip"
	"testing"
)

func TestStaticGatewayConnectedSourcesAndInterfaces(t *testing.T) {
	c := Default()
	c.Interfaces = []Interface{{ID: "lan", Name: "br0"}, {ID: "wan", Name: "eth0"}, {ID: "dup", Name: "first"}, {ID: "dup", Name: "second"}, {ID: "", Name: "empty-alias"}}
	c.Networks = []Network{{Enabled: true, Interface: "lan", RouterAddress: "10.0.0.1/24"}, {Enabled: false, Interface: "lan", RouterAddress: "10.1.0.1/24"}, {Enabled: true, Interface: "dup", RouterAddress: "10.2.0.1/24"}, {Enabled: true, Interface: "lan", RouterAddress: "bad"}, {Enabled: true, Interface: "lan", RouterAddress: "2001:db8::1/64"}, {Enabled: true, RouterAddress: "10.9.0.1/24"}}
	c.WANs = []WAN{{Enabled: true, Proto: "static", Interface: "wan", Address: "192.0.2.1/24"}, {Enabled: true, Proto: "dhcp", Interface: "wan", Address: "198.51.100.1/24"}, {Enabled: true, Proto: "pppoe", Underlay: "static", Interface: "wan", Address: "203.0.113.1/24"}}
	c.VPNServers = []VPNServer{{Enabled: true, Subnet: "10.3.0.1/24"}}
	c.Routing.Static = []StaticRoute{{Enabled: true, Destination: "10.4.0.0/24", Interface: "lan", Table: "main"}, {Enabled: true, Destination: "10.5.0.0/24", Interface: "lan"}, {Enabled: true, Destination: "10.6.0.0/24", Interface: "lan", Type: "blackhole"}, {Enabled: true, Destination: "10.7.0.0/24", Interface: "lan", Gateway: "10.0.0.2"}, {Enabled: true, Destination: "default", Interface: "lan"}}
	names := map[string]string{}
	for _, tc := range []struct {
		ip, iface, table string
		want             bool
	}{
		{"10.0.0.2", "", "", true}, {"10.0.0.2", "lan", "", true}, {"10.0.0.2", "br0", "", true}, {"10.0.0.2", "missing", "", false},
		{"10.1.0.2", "lan", "", false}, {"10.2.0.2", "first", "", true}, {"10.2.0.2", "second", "", false},
		{"192.0.2.2", "eth0", "", true}, {"198.51.100.2", "eth0", "", false}, {"203.0.113.2", "wan", "", true},
		{"10.3.0.2", "", "", true}, {"10.3.0.2", "lan", "", false},
		{"10.4.0.2", "br0", "main", true}, {"10.4.0.2", "br0", "", false}, {"10.4.0.2", "", "main", true},
		{"10.5.0.2", "lan", "", true}, {"10.5.0.2", "lan", "main", false},
		{"10.6.0.2", "lan", "", false}, {"10.7.0.2", "lan", "", false}, {"10.8.0.2", "lan", "", false},
		{"2001:db8::2", "br0", "", true}, {"2001:db8:1::2", "br0", "", false}, {"10.9.0.2", "empty-alias", "", true},
	} {
		r := StaticRoute{Interface: tc.iface, Table: tc.table}
		if got := c.staticGatewayConnected(r, netip.MustParseAddr(tc.ip), names); got != tc.want {
			t.Errorf("%+v got %t", tc, got)
		}
	}
}
func TestRoutingValidationRefreshesInterfaceNames(t *testing.T) {
	c := Default()
	c.Interfaces = []Interface{{ID: "lan", Name: "br0"}}
	c.Networks = []Network{{Enabled: true, Interface: "lan", RouterAddress: "10.0.0.1/24"}}
	c.Routing.Static = []StaticRoute{{Enabled: true, Destination: "default", Interface: "br0", Gateway: "10.0.0.2"}}
	check := func(want int) {
		t.Helper()
		var r ValidationResult
		c.validateRouting(&r)
		if len(r.Problems) != want {
			t.Fatalf("got %v want %d", r.Problems, want)
		}
		for _, p := range r.Problems {
			if p.Severity != "warning" || p.Path != "routing.static[0].gateway" {
				t.Fatal(p)
			}
		}
	}
	check(0)
	c.Interfaces[0].Name = "br1"
	check(1)
	c.Routing.Static[0].Interface = "br1"
	check(0)
	c.Interfaces = nil
	check(1)
	c.Interfaces = []Interface{{ID: "lan", Name: "br1"}}
	check(0)
}

package config

import (
	"fmt"
	"net/netip"
	"testing"
)

func BenchmarkSharedStaticGateway(b *testing.B) {
	for _, count := range []int{8, 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			c := Default()
			for i := 0; i < count; i++ {
				c.Routing.Static = append(c.Routing.Static, StaticRoute{
					Enabled: true, Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), Gateway: "192.0.2.1",
				})
			}
			b.ReportAllocs()
			for b.Loop() {
				result := c.Validate()
				if len(result.Problems) < count {
					b.Fatal("missing gateway warnings")
				}
			}
		})
	}
}

func TestSharedGatewayWarningsKeepRouteOrderAndScope(t *testing.T) {
	c := Default()
	c.Routing.Static = []StaticRoute{
		{Enabled: true, Destination: "192.0.2.1", Interface: "eth0"},
		{Enabled: true, Destination: "10.1.0.0/16", Interface: "eth0", Gateway: "192.0.2.1"},
		{Enabled: true, Destination: "10.2.0.0/16", Interface: "eth1", Gateway: "192.0.2.1"},
		{Enabled: true, Destination: "10.3.0.0/16", Interface: "eth0", Gateway: "192.0.2.1", Table: "local"},
		{Enabled: true, Destination: "10.4.0.0/16", Interface: "eth1", Gateway: "192.0.2.1", Table: "main"},
	}
	for _, warnings := range [][]int{{2, 3, 4}, {1, 2, 3, 4}} {
		var result ValidationResult
		c.validateRouting(&result)
		if len(result.Problems) != len(warnings) {
			t.Fatalf("unexpected problems: %+v", result.Problems)
		}
		for i, route := range warnings {
			p := result.Problems[i]
			if p.Path != fmt.Sprintf("routing.static[%d].gateway", route) || p.Severity != "warning" {
				t.Fatalf("unexpected problem: %+v", p)
			}
		}
		c.Routing.Static[0].Enabled = false
	}
}

func TestStaticGatewayConnectedSourcesAndInterfaces(t *testing.T) {
	c := Default()
	c.Interfaces = []Interface{{ID: "lan", Name: "br0"}, {ID: "wan", Name: "eth0"}, {ID: "dup", Name: "first"}, {ID: "dup", Name: "second"}, {ID: "", Name: "empty-alias"}}
	c.Networks = []Network{{Enabled: true, Interface: "lan", RouterAddress: "10.0.0.1/24"}, {Enabled: false, Interface: "lan", RouterAddress: "10.1.0.1/24"}, {Enabled: true, Interface: "dup", RouterAddress: "10.2.0.1/24"}, {Enabled: true, Interface: "lan", RouterAddress: "bad"}, {Enabled: true, Interface: "lan", RouterAddress: "2001:db8::1/64"}, {Enabled: true, RouterAddress: "10.9.0.1/24"}}
	c.WANs = []WAN{{Enabled: true, Proto: "static", Interface: "wan", Address: "192.0.2.1/24"}, {Enabled: true, Proto: "dhcp", Interface: "wan", Address: "198.51.100.1/24"}, {Enabled: true, Proto: "pppoe", Underlay: "static", Interface: "wan", Address: "203.0.113.1/24"}}
	c.VPNServers = []VPNServer{{Enabled: true, Subnet: "10.3.0.1/24"}}
	c.Routing.Static = []StaticRoute{{Enabled: true, Destination: "10.4.0.0/24", Interface: "lan", Table: "main"}, {Enabled: true, Destination: "10.5.0.0/24", Interface: "lan"}, {Enabled: true, Destination: "10.6.0.0/24", Interface: "lan", Type: "blackhole"}, {Enabled: true, Destination: "10.7.0.0/24", Interface: "lan", Gateway: "10.0.0.2"}, {Enabled: true, Destination: "default", Interface: "lan"}}
	names := map[string]string{}
	var direct directRouteIndex
	for _, tc := range []struct {
		ip, iface, table string
		want             bool
	}{
		{"10.0.0.2", "", "", true}, {"10.0.0.2", "lan", "", true}, {"10.0.0.2", "br0", "", true}, {"10.0.0.2", "missing", "", false},
		{"10.1.0.2", "lan", "", false}, {"10.2.0.2", "first", "", true}, {"10.2.0.2", "second", "", false},
		{"192.0.2.2", "eth0", "", true}, {"198.51.100.2", "eth0", "", false}, {"203.0.113.2", "wan", "", true},
		{"10.3.0.2", "", "", true}, {"10.3.0.2", "lan", "", false},
		{"10.4.0.2", "br0", "main", true}, {"10.4.0.2", "br0", "", true}, {"10.4.0.2", "br0", "local", false}, {"10.4.0.2", "", "main", true},
		{"10.5.0.2", "lan", "", true}, {"10.5.0.2", "lan", "main", true}, {"10.5.0.2", "lan", "local", false},
		{"10.6.0.2", "lan", "", false}, {"10.7.0.2", "lan", "", false}, {"10.8.0.2", "lan", "", false},
		{"2001:db8::2", "br0", "", true}, {"2001:db8:1::2", "br0", "", false}, {"10.9.0.2", "empty-alias", "", true},
	} {
		r := StaticRoute{Interface: tc.iface, Table: tc.table}
		if got := c.staticGatewayConnected(r, netip.MustParseAddr(tc.ip), names, &direct); got != tc.want {
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

func TestGatewayWarningAfterChangingTable(t *testing.T) {
	c := Default()
	c.Routing.Static = []StaticRoute{
		{Enabled: true, Destination: "192.0.2.0/24", Interface: "eth0"},
		{Enabled: true, Destination: "198.51.100.0/24", Interface: "eth0", Gateway: "192.0.2.1"},
	}
	for _, tc := range []struct {
		direct, via string
		warn        bool
	}{
		{"main", "", false}, {"", "main", false}, {"local", "main", true}, {"local", "local", false}, {"", "local", true}, {"", "", false},
	} {
		c.Routing.Static[0].Table, c.Routing.Static[1].Table = tc.direct, tc.via
		r := c.Validate()
		p, found := problemAt(r, "routing.static[1].gateway")
		if r.HasErrors() || found != tc.warn || (found && p.Severity != "warning") {
			t.Fatalf("%+v: %v", tc, r.Problems)
		}
	}
}

func TestGatewayThroughDirectHostRoute(t *testing.T) {
	for _, gateway := range []string{"192.0.2.1", "2001:db8::1"} {
		c := Default()
		c.Routing.Static = []StaticRoute{
			{Enabled: true, Destination: gateway, Interface: "eth0"},
			{Enabled: true, Destination: "default", Gateway: gateway, Interface: "eth0"},
		}
		host := netip.MustParseAddr(gateway)
		for _, tc := range []struct {
			destination, iface string
			warn               bool
		}{
			{gateway, "eth0", false}, {host.Next().String(), "eth0", true},
			{gateway, "eth1", true}, {netip.PrefixFrom(host, host.BitLen()).String(), "eth0", false},
			{gateway, "eth0", false},
		} {
			c.Routing.Static[0].Destination, c.Routing.Static[0].Interface = tc.destination, tc.iface
			r := c.Validate()
			p, found := problemAt(r, "routing.static[1].gateway")
			if r.HasErrors() || found != tc.warn || (found && p.Severity != "warning") {
				t.Fatalf("%+v: %v", tc, r.Problems)
			}
		}
	}
}

func TestDirectRoutesWithDistinctGateways(t *testing.T) {
	c := Default()
	c.Interfaces = []Interface{{ID: "port", Name: "eth0"}, {ID: "port", Name: "duplicate"}}
	c.Routing.Static = []StaticRoute{
		{Enabled: true, Interface: "port", Destination: "2001:db8::17/64"},
		{Enabled: true, Interface: "port", Destination: "fe80::1%eth0"},
		{Enabled: true, Interface: "port", Destination: "192.0.2.17/24", Table: "local"},
	}
	for i, gateway := range []string{"2001:db8::2", "2001:db8::3%eth0", "fe80::1%eth0", "fe80::1%eth1", "192.0.2.1", "192.0.2.2", "2001:db8::4"} {
		r := StaticRoute{Enabled: true, Interface: "eth0", Destination: "default", Gateway: gateway, Metric: i + 1}
		if i == 5 {
			r.Table = "local"
		}
		if i == 6 {
			r.Interface = "duplicate"
		}
		c.Routing.Static = append(c.Routing.Static, r)
	}
	for _, want := range [][]int{{4, 6, 7, 9}, {3, 4, 6, 7, 9}} {
		var result ValidationResult
		c.validateRouting(&result)
		if len(result.Problems) != len(want) {
			t.Fatal(result.Problems)
		}
		for i, index := range want {
			p := result.Problems[i]
			if p.Path != fmt.Sprintf("routing.static[%d].gateway", index) || p.Severity != "warning" {
				t.Fatal(p)
			}
		}
		c.Routing.Static[0].Enabled = false
	}
}

package config

import (
	"reflect"
	"testing"
)

func TestIsolationDestinationsFilteringAndFreshChanges(t *testing.T) {
	c := Default()
	c.Firewall.Enabled = true
	c.Networks = []Network{
		{ID: "self", Enabled: true, Isolated: true, RouterAddress: "192.168.1.7/24"},
		{ID: "plain", Enabled: true, RouterAddress: "192.168.2.1/24"},
		{ID: "off", Isolated: true, RouterAddress: "192.168.3.1/24"},
		{ID: "invalid", Enabled: true, Isolated: true, RouterAddress: "invalid"},
		{ID: "ipv6", Enabled: true, Isolated: true, RouterAddress: "2001:db8::1/64"},
	}
	c.VPNServers = []VPNServer{
		{ID: "self", Enabled: true, Isolated: true, Subnet: "10.1.0.1/24"},
		{ID: "peer", Enabled: true, Isolated: true, Subnet: "10.2.0.1/24"},
		{ID: "duplicate-subnet", Enabled: true, Isolated: true, Subnet: "10.2.0.9/24"},
		{ID: "plain", Enabled: true, Subnet: "10.3.0.1/24"},
		{ID: "off", Isolated: true, Subnet: "10.4.0.1/24"},
		{ID: "invalid", Enabled: true, Isolated: true, Subnet: "invalid"},
	}
	server := VPNServer{ID: "self"}
	check := func(want []string) {
		t.Helper()
		if got := c.IsolationDestinations(server); !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v want %#v", got, want)
		}
	}
	check([]string{"192.168.1.0/24", "10.2.0.0/24", "10.2.0.0/24"})
	server.Isolated = true
	check([]string{"192.168.1.0/24", "192.168.2.0/24", "10.2.0.0/24", "10.2.0.0/24", "10.3.0.0/24"})
	c.Firewall.Enabled = false
	check(nil)
	c.Firewall.Enabled = true
	server.Isolated = false
	for i := range c.Networks {
		c.Networks[i].Isolated = false
	}
	for i := range c.VPNServers {
		c.VPNServers[i].Isolated = false
	}
	check(nil)
	c.VPNServers[1].Isolated = true
	c.VPNServers[1].Subnet = "10.9.1.7/16"
	check([]string{"10.9.0.0/16"})
	c.VPNServers[1].Enabled = false
	check(nil)
}

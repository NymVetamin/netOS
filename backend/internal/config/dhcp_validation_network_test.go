package config

import (
	"strings"
	"testing"
)

func TestDHCPReservationNetworkChecks(t *testing.T) {
	for _, tc := range []struct{ name, address, ip, gateway, want string }{
		{"client", "192.0.2.1/24", "192.0.2.2", "", ""},
		{"router", "192.0.2.1/24", "192.0.2.1", "", "адрес роутера"},
		{"gateway", "192.0.2.1/24", "192.0.2.2", "192.0.2.2", "адрес роутера"},
		{"network", "192.0.2.1/24", "192.0.2.0", "", "адрес сети"},
		{"broadcast", "192.0.2.1/24", "192.0.2.255", "", "широковещательный"},
		{"outside", "192.0.2.1/24", "198.51.100.1", "", "не принадлежит"},
		{"invalid prefix", "bad", "192.0.2.2", "", "не принадлежит"},
		{"ipv6 prefix", "2001:db8::1/64", "192.0.2.2", "", "не принадлежит"},
		{"invalid client", "192.0.2.1/24", "bad", "", "некорректный IP"},
		{"31 client", "192.0.2.1/31", "192.0.2.0", "", ""},
		{"32 router", "192.0.2.1/32", "192.0.2.1", "", "адрес роутера"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.Networks = []Network{{ID: "lan", RouterAddress: tc.address}}
			c.Networks[0].DHCPPool.Gateway = tc.gateway
			c.DHCP.Reservations = []Reservation{{ID: "r", MAC: "02:00:00:00:00:01", IP: tc.ip, Network: "lan"}}
			var r ValidationResult
			c.validateDHCP(&r)
			if tc.want == "" {
				if len(r.Problems) != 0 {
					t.Fatal(r.Problems)
				}
			} else if len(r.Problems) != 1 || !strings.Contains(r.Problems[0].Message, tc.want) {
				t.Fatal(r.Problems)
			}
		})
	}
}

func TestDHCPReservationDuplicateNetworksAndFreshChanges(t *testing.T) {
	c := Default()
	c.Networks = []Network{{ID: "lan", RouterAddress: "bad"}, {ID: "lan", RouterAddress: "192.0.2.1/24"}}
	c.DHCP.Reservations = []Reservation{{ID: "r", MAC: "02:00:00:00:00:01", IP: "192.0.2.2", Network: "lan"}}
	check := func(want string, count int) {
		t.Helper()
		var r ValidationResult
		c.validateDHCP(&r)
		if len(r.Problems) != count {
			t.Fatalf("got %v want %d", r.Problems, count)
		}
		for _, p := range r.Problems {
			if !strings.Contains(p.Message, want) {
				t.Fatal(p)
			}
		}
	}
	// Membership uses the first ID even if a later duplicate contains the address.
	check("не принадлежит", 1)
	c.Networks[0].RouterAddress = "192.0.2.1/24"
	check("", 0)
	// All matching network entries still contribute reserved-address errors.
	c.Networks[0].DHCPPool.Gateway = "192.0.2.2"
	c.Networks[1].DHCPPool.Gateway = "192.0.2.2"
	check("адрес роутера", 2)
	c.Networks[0].DHCPPool.Gateway = ""
	c.Networks[1].DHCPPool.Gateway = ""
	check("", 0)
	c.Networks = nil
	check("", 2)
	c.DHCP.Reservations = nil
	c.DHCP.Provider = "unknown"
	check("неизвестный сервер", 1)
	c.DHCP.Provider = "kea"
	c.DHCP.AdvancedOptions = "anything"
	check("не поддерживает", 1)
	c.DHCP.AdvancedOptions = ""
	check("", 0)
}

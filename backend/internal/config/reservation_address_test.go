package config

import "testing"

func TestReservationRejectsInfrastructureAddresses(t *testing.T) {
	for _, ip := range []string{"192.168.50.0", "192.168.50.1", "192.168.50.254", "192.168.50.255"} {
		t.Run(ip, func(t *testing.T) {
			cfg := validationFixture()
			cfg.Networks[0].DHCPPool.Gateway = "192.168.50.254"
			cfg.DHCP.Reservations = []Reservation{{ID: "r1", Enabled: true, MAC: "02:00:00:00:00:01", IP: ip, Network: "home"}}
			if !hasErrorAt(cfg.Validate(), "dhcp.reservations[0].ip") {
				t.Fatal("reserved infrastructure address accepted for a DHCP client")
			}
		})
	}
}

func TestReservationAllowsUsableAddressesInsideAndOutsidePool(t *testing.T) {
	for _, ip := range []string{"192.168.50.2", "192.168.50.100", "192.168.50.200", "192.168.50.253"} {
		cfg := validationFixture()
		cfg.DHCP.Reservations = []Reservation{{ID: "r1", Enabled: true, MAC: "02:00:00:00:00:01", IP: ip, Network: "home"}}
		if hasErrorAt(cfg.Validate(), "dhcp.reservations[0].ip") {
			t.Errorf("usable reservation address rejected: %s", ip)
		}
	}
}

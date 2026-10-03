package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestClientNameIsAssignedToDHCPLease(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.Enabled = true
	cfg.DHCP.Provider = "dnsmasq"
	cfg.Clients = []config.Client{{ID: "client", MAC: "02:00:00:00:00:10", Name: "qa-device1"}}
	got := NewDnsmasq(nil).Render(cfg)
	if !strings.Contains(got, "dhcp-host=02:00:00:00:00:10,qa-device1") {
		t.Fatal("client name missing from DHCP hostname mapping")
	}
	cfg.Clients[0].Name = "shown to the user"
	got = NewDnsmasq(nil).Render(cfg)
	if strings.Contains(got, "dhcp-host=02:00:00:00:00:10,shown") {
		t.Fatal("display name with spaces was passed to dnsmasq as a hostname")
	}
}

func TestReservationHostnameOverridesClientDisplayName(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.Enabled = true
	cfg.DHCP.Provider = "dnsmasq"
	cfg.Clients = []config.Client{{ID: "client", MAC: "02:00:00:00:00:10", Name: "old-client-name"}}
	cfg.DHCP.Reservations = []config.Reservation{{ID: "reserved", MAC: "02:00:00:00:00:10", IP: "192.0.2.20", Hostname: "new-reservation-name", Enabled: true}}
	got := NewDnsmasq(nil).Render(cfg)
	if !strings.Contains(got, "dhcp-host=02:00:00:00:00:10,new-reservation-name,192.0.2.20") || strings.Contains(got, "dhcp-host=02:00:00:00:00:10,old-client-name") {
		t.Fatalf("reservation hostname lost to client display name:\n%s", got)
	}
}

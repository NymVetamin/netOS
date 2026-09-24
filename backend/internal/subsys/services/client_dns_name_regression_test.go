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

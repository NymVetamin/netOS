package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func providerTestConfig() *config.Config {
	cfg := config.Default()
	cfg.DHCP.Enabled = true
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "br0", Enabled: true}}
	cfg.Networks = []config.Network{{
		ID: "office", Interface: "lan", RouterAddress: "192.168.50.1/24", Enabled: true,
		DHCPPool: config.DHCPPool{Enabled: true, Start: "192.168.50.100", End: "192.168.50.200", LeaseTime: 3600, Domain: "lan", Options: map[string]string{"66": "pxe.lan", "224": "hello"}},
	}}
	cfg.DHCP.Reservations = []config.Reservation{{ID: "printer", Enabled: true, MAC: "02:00:00:00:00:01", IP: "192.168.50.10", Hostname: "printer", Network: "office"}}
	cfg.Clients = []config.Client{{MAC: "02:00:00:00:00:02", Blocked: true}}
	return cfg
}

func TestISCDHCPRender(t *testing.T) {
	cfg := providerTestConfig()
	cfg.DHCP.Provider = "isc-dhcp-server"
	out := NewISCDHCP(&serviceRunner{}).Render(cfg)
	for _, want := range []string{"subnet 192.168.50.0 netmask 255.255.255.0", "range 192.168.50.100 192.168.50.200", "fixed-address 192.168.50.10", "deny booting"} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге ISC нет %q:\n%s", want, out)
		}
	}
}

func TestKeaDHCPRender(t *testing.T) {
	cfg := providerTestConfig()
	cfg.DHCP.Provider = "kea"
	out := NewKeaDHCP(&serviceRunner{}).Render(cfg)
	var root map[string]any
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		t.Fatalf("невалидный JSON Kea: %v", err)
	}
	for _, want := range []string{`"interfaces"`, `"br0"`, `"192.168.50.0/24"`, `"DROP"`, `"192.168.50.10"`, `"/var/lib/kea/netos-leases4.csv"`} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге Kea нет %q:\n%s", want, out)
		}
	}
}

func TestKeaUnitCreatesRequiredRuntimeDirectory(t *testing.T) {
	unit := renderKeaUnit()
	if !strings.Contains(unit, "RuntimeDirectory=kea") {
		t.Fatalf("Kea unit does not create /run/kea:\n%s", unit)
	}
}

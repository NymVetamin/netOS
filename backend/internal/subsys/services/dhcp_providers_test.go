package services

import (
	"encoding/json"
	"fmt"
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

func iscCollisionConfig() *config.Config {
	cfg := providerTestConfig()
	for i, id := range []string{"pc_1", "pc-1", "pc.1", "PC-1", "blocked-1"} {
		cfg.DHCP.Reservations = append(cfg.DHCP.Reservations, config.Reservation{
			ID: id, Enabled: true, MAC: fmt.Sprintf("02:00:00:00:01:%02x", i),
			IP: fmt.Sprintf("192.168.50.%d", 30+i), Network: "office", Hostname: "client",
		})
	}
	return cfg
}

func TestISCDHCPKeepsDistinctReservationsAndBlockedHosts(t *testing.T) {
	cfg := iscCollisionConfig()
	d := NewISCDHCP(nil)
	out := d.Render(cfg)
	if out != d.Render(cfg) {
		t.Fatal("unstable config")
	}
	names := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "host ") {
			name := strings.Fields(line)[1]
			if names[name] {
				t.Fatalf("duplicate host %s", name)
			}
			names[name] = true
		}
	}
	if len(names) != len(cfg.DHCP.Reservations)+1 || !names["netos-printer"] || !names["netos-blocked-1"] {
		t.Fatal(names)
	}
	for _, r := range cfg.DHCP.Reservations {
		if !strings.Contains(out, fmt.Sprintf("hardware ethernet %s;\n  fixed-address %s;\n  option host-name %q;", r.MAC, r.IP, r.Hostname)) {
			t.Fatalf("missing reservation %s", r.ID)
		}
	}
	cfg.DHCP.Reservations[1].Enabled = false
	after := d.Render(cfg)
	if !strings.Contains(after, "host netos-pc-1 {\n  hardware ethernet 02:00:00:00:01:01;") ||
		strings.Contains(after, "hardware ethernet 02:00:00:00:01:00;") {
		t.Fatal("disabled reservation still owns its declaration")
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
	for _, want := range []string{`"interfaces"`, `"br0"`, `"service-sockets-max-retries": 0`, `"192.168.50.0/24"`, `"DROP"`, `"192.168.50.10"`, `"` + strings.ReplaceAll(keaLeasePath, `\`, `\\`) + `"`} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге Kea нет %q:\n%s", want, out)
		}
	}
}

func TestBlockedReservationMACSpellings(t *testing.T) {
	for name, render := range map[string]func(*config.Config) string{
		"ISC": NewISCDHCP(nil).Render, "Kea": NewKeaDHCP(nil).Render,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := providerTestConfig()
			cfg.Clients[0].MAC = "02:aa:11:bb:22:cc"
			res := cfg.DHCP.Reservations[0]
			res.ID, res.IP, res.MAC = "blocked", "192.168.50.11", cfg.Clients[0].MAC
			cfg.DHCP.Reservations = append(cfg.DHCP.Reservations, res)
			want := render(cfg)
			if strings.Contains(want, res.IP) || !strings.Contains(want, cfg.Clients[0].MAC) ||
				!strings.Contains(want, cfg.DHCP.Reservations[0].IP) {
				t.Fatal("invalid canonical fixture")
			}
			for _, mac := range []string{"02-AA-11-BB-22-CC", "02aa.11bb.22cc", "02:AA:11:BB:22:CC"} {
				cfg.DHCP.Reservations[1].MAC = mac
				if got := render(cfg); got != want {
					t.Errorf("blocked reservation differs for %s", mac)
				}
				cfg.Clients[0].Blocked = false
				got := render(cfg)
				if !strings.Contains(got, res.IP) || cfg.DHCP.Reservations[1].MAC != mac {
					t.Errorf("unblocked reservation lost for %s", mac)
				}
				cfg.Clients[0].Blocked = true
			}
		})
	}
}

func TestKeaUnitCreatesRequiredRuntimeDirectory(t *testing.T) {
	unit := renderKeaUnit()
	if !strings.Contains(unit, "RuntimeDirectory=kea") {
		t.Fatalf("Kea unit does not create /run/kea:\n%s", unit)
	}
}

package wifi

import (
	"context"
	"github.com/netos-router/netos/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitRequiresExistingBridgesBeforeHostapd(t *testing.T) {
	cfg := wifiConfig()
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: "guest", Name: "br-guest", Type: "bridge", Enabled: true})
	cfg.Networks = append(cfg.Networks, config.Network{ID: "guest", Interface: "guest", Enabled: true})
	cfg.WiFi[0].SSIDs = append(cfg.WiFi[0].SSIDs,
		config.WiFiSSID{ID: "third", SSID: "Third", Network: "guest", Enabled: true, Security: "open"},
		config.WiFiSSID{ID: "off", SSID: "Off", Network: "missing", Enabled: false})
	s := New(&fakeRunner{}, filepath.Join(t.TempDir(), "state"))
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	_, path := s.paths(cfg.WiFi[0])
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	for _, bridge := range []string{"br0", "br-guest"} {
		guard := "ExecStartPre=/usr/bin/test -d /sys/class/net/" + bridge + "/bridge\n"
		if strings.Count(unit, guard) != 1 || strings.Index(unit, guard) > strings.Index(unit, "ExecStart=/usr/sbin/hostapd") {
			t.Fatalf("missing unique pre-start bridge guard %q in %s", bridge, unit)
		}
	}
	if strings.Contains(unit, "missing/bridge") {
		t.Fatal("disabled SSID adds a bridge prerequisite")
	}
}

func TestDuplicateNetworkBridgeSelectionAfterEdits(t *testing.T) {
	cfg := wifiConfig()
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: "alt", Name: "br1"})
	cfg.Networks = append(cfg.Networks, config.Network{ID: "home", Interface: "alt", Enabled: true})
	s := testWiFiSubsystem(t, &fakeRunner{})
	check := func(wantGuard string) {
		t.Helper()
		if err := s.Apply(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		conf, unit := s.paths(cfg.WiFi[0])
		text, err := os.ReadFile(conf)
		if err != nil || strings.Count(string(text), "bridge=br1\n") != 2 {
			t.Fatal("wrong configured bridge", err)
		}
		data, err := os.ReadFile(unit)
		if err != nil {
			t.Fatal(err)
		}
		var guards []string
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ExecStartPre=") {
				guards = append(guards, line)
			}
		}
		if strings.Join(guards, "\n") != wantGuard {
			t.Fatalf("wrong bridge guards: %q", guards)
		}
	}
	check("ExecStartPre=/usr/bin/test -d /sys/class/net/br0/bridge")
	cfg.Networks[0].Enabled = false
	check("")
	cfg.Networks[0].Enabled = true
	cfg.Interfaces[0].Name = "br2"
	check("ExecStartPre=/usr/bin/test -d /sys/class/net/br2/bridge")
}

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

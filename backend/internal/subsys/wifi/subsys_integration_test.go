//go:build linux

package wifi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationHostapdLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, command := range []string{"hostapd", "hostapd_cli", "iw", "modprobe"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
	if _, err := os.Stat("/sys/module/mac80211_hwsim"); err == nil {
		t.Skip("refusing to disrupt an existing mac80211_hwsim instance")
	}
	ctx := context.Background()
	runner := system.NewExec()
	if _, err := runner.Run(ctx, "modprobe", "mac80211_hwsim", "radios=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "modprobe", "-r", "mac80211_hwsim") })
	out, err := runner.Run(ctx, "iw", "dev")
	if err != nil {
		t.Fatal(err)
	}
	device := ""
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "Interface" {
			device = fields[1]
			break
		}
	}
	if device == "" {
		t.Fatal("mac80211_hwsim did not create a radio interface")
	}
	const bridge = "br-wifi997"
	if _, err := runner.Run(ctx, "ip", "link", "show", bridge); err == nil {
		t.Skipf("refusing to reuse existing %s", bridge)
	}
	if _, err := runner.Run(ctx, "ip", "link", "add", "name", bridge, "type", "bridge"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "link", "delete", bridge) })
	if _, err := runner.Run(ctx, "ip", "link", "set", "dev", bridge, "up"); err != nil {
		t.Fatal(err)
	}

	root, err := os.MkdirTemp("/var/lib", "netos-wifi-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	s := New(runner, root)
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "hostapd", Installed: true}}
	cfg.Interfaces = []config.Interface{{ID: "wifi-bridge", Name: bridge, Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "wifi-net", Name: "Wi-Fi test", Interface: "wifi-bridge", RouterAddress: "192.0.2.1/24", Zone: "lan", Enabled: true}}
	cfg.WiFi = []config.WiFiRadio{{
		ID: "integration", Device: device, Enabled: true, Band: "2.4", Channel: 1, Width: 20, Country: "US",
		SSIDs: []config.WiFiSSID{{ID: "test", SSID: "netOS-integration", Enabled: true, Security: "wpa2", Password: "integration-only", Network: "wifi-net"}},
	}}
	t.Cleanup(func() { _ = s.Apply(context.Background(), config.Default()) })
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("integration config is invalid: %+v", result.Problems)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := runner.Run(ctx, "iw", "dev", device, "info")
	if err != nil || !strings.Contains(info, "type AP") || !strings.Contains(info, "channel 1") {
		t.Fatalf("radio did not enter AP mode: %q (%v)", info, err)
	}
	if err := s.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	conf, unit := s.paths(cfg.WiFi[0])
	for _, path := range []string{conf, unit, filepath.Join(root, "owned-wifi.json")} {
		if _, err := os.Stat(path); err == nil && path != filepath.Join(root, "owned-wifi.json") {
			t.Fatalf("owned Wi-Fi artifact was not removed: %s", path)
		}
	}
}

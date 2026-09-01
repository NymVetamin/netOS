//go:build linux

package netiface

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationManagedPPPoELifecycle(t *testing.T) {
	requireManagedWANIntegration(t, "pppd", "pppoe-server")
	requireNoManagedWANArtifacts(t)
	ensureServerPlugin(t)
	setupLink(t)
	setupSecrets(t)

	ctx := context.Background()
	runner := system.NewExec()
	s := NewWAN(runner)
	s.OwnedAddressPath = "/run/netos-qa-owned-wan-addresses.json"
	s.OwnedRoutePath = "/run/netos-qa-owned-wan-routes.json"
	s.OwnedLNSRoutePath = "/run/netos-qa-owned-l2tp-routes.json"
	s.PPPoETimeout, s.PPPoePoll = 40*time.Second, 100*time.Millisecond
	t.Cleanup(func() { cleanupManagedWANTest("pppoe", "qalife", testClientIface, s) })

	startServer(t)
	w := config.WAN{ID: "qalife", Name: "PPPoE lifecycle", Interface: "if-qalife", Enabled: true,
		Proto: "pppoe", Username: testUser, Password: testPassword, Metric: 4200}
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "if-qalife", Name: testClientIface, Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{w}

	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	pid := managedUnitPID(t, pppoeUnitName(w.ID))
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if got := managedUnitPID(t, pppoeUnitName(w.ID)); got != pid {
		t.Fatalf("idempotent PPPoE Apply restarted the live session: %s -> %s", pid, got)
	}
	if err := s.Apply(ctx, emptyWANConfig()); err != nil {
		t.Fatal(err)
	}
	assertManagedWANRemoved(t, "pppoe", w.ID)
}

func TestIntegrationManagedL2TPLifecycle(t *testing.T) {
	requireManagedWANIntegration(t, "pppd", "xl2tpd")
	requireNoManagedWANArtifacts(t)
	setupL2TPLink(t)
	setupL2TPSecrets(t)
	startLNS(t)

	ctx := context.Background()
	runner := system.NewExec()
	s := NewWAN(runner)
	s.OwnedAddressPath = "/run/netos-qa-owned-wan-addresses.json"
	s.OwnedRoutePath = "/run/netos-qa-owned-wan-routes.json"
	s.OwnedLNSRoutePath = "/run/netos-qa-owned-l2tp-routes.json"
	s.PPPoETimeout, s.PPPoePoll = 45*time.Second, 100*time.Millisecond
	t.Cleanup(func() { cleanupManagedWANTest("l2tp", "qalife", l2tpClientIf, s) })

	w := config.WAN{ID: "qalife", Name: "L2TP lifecycle", Interface: "if-qalife", Enabled: true,
		Proto: "l2tp", Underlay: "static", Address: l2tpClientAddr + "/24", Gateway: l2tpServerAddr,
		Server: l2tpServerAddr, Username: l2tpUser, Password: l2tpPassword, Metric: 4300}
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "if-qalife", Name: l2tpClientIf, Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{w}

	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	pid := managedUnitPID(t, l2tpUnitName(w.ID))
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if got := managedUnitPID(t, l2tpUnitName(w.ID)); got != pid {
		t.Fatalf("idempotent L2TP Apply restarted the live tunnel: %s -> %s", pid, got)
	}
	if err := s.Apply(ctx, emptyWANConfig()); err != nil {
		t.Fatal(err)
	}
	assertManagedWANRemoved(t, "l2tp", w.ID)
}

func requireManagedWANIntegration(t *testing.T, commands ...string) {
	t.Helper()
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	commands = append(commands, "ip", "systemctl")
	for _, command := range commands {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
}

func requireNoManagedWANArtifacts(t *testing.T) {
	t.Helper()
	patterns := []string{
		filepath.Join(systemdUnitDir, "netos-dhcp-*.service"),
		filepath.Join(systemdUnitDir, "netos-pppoe-*.service"),
		filepath.Join(systemdUnitDir, "netos-l2tp-*.service"),
		filepath.Join(pppoeConfDir, "pppoe-*.conf"),
		filepath.Join(pppoeConfDir, "l2tp-*.conf"),
		filepath.Join(pppoeConfDir, "l2tp-*.ppp"),
	}
	for _, pattern := range patterns {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			t.Skipf("managed WAN artifacts already exist; refusing broad lifecycle cleanup: %v", matches)
		}
	}
}

func emptyWANConfig() *config.Config {
	cfg := config.Default()
	cfg.Interfaces = nil
	cfg.WANs = nil
	return cfg
}

func managedUnitPID(t *testing.T, unit string) string {
	t.Helper()
	out, err := exec.Command("systemctl", "show", unit, "-p", "MainPID", "--value").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) == "0" {
		t.Fatalf("unit %s has no live PID: %v (%s)", unit, err, out)
	}
	return strings.TrimSpace(string(out))
}

func assertManagedWANRemoved(t *testing.T, protocol, id string) {
	t.Helper()
	paths := []string{filepath.Join(systemdUnitDir, "netos-"+protocol+"-"+id+".service")}
	if protocol == "pppoe" {
		paths = append(paths, pppoeConfPath(id))
	} else {
		paths = append(paths, l2tpConfPath(id), l2tpPPPPath(id))
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("managed artifact remains after cleanup: %s (%v)", path, err)
		}
	}
	if linkExists("ppp-" + id) {
		t.Fatalf("managed PPP link remains after cleanup: ppp-%s", id)
	}
}

func cleanupManagedWANTest(protocol, id, iface string, s *WAN) {
	unit := "netos-" + protocol + "-" + id + ".service"
	_ = exec.Command("systemctl", "disable", "--now", unit).Run()
	_ = os.Remove(filepath.Join(systemdUnitDir, unit))
	_ = os.Remove(pppoeConfPath(id))
	_ = os.Remove(l2tpConfPath(id))
	_ = os.Remove(l2tpPPPPath(id))
	_ = os.Remove(s.OwnedAddressPath)
	_ = os.Remove(s.OwnedRoutePath)
	_ = os.Remove(s.OwnedLNSRoutePath)
	_ = exec.Command("ip", "route", "del", l2tpServerAddr+"/32", "via", l2tpServerAddr, "dev", iface, "proto", fmt.Sprint(config.RouteProto)).Run()
	_ = exec.Command("systemctl", "daemon-reload").Run()
}

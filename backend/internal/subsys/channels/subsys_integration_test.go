//go:build linux

package channels

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationWireGuardLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("интеграционный тест: NETOS_INTEGRATION=1 и root")
	}
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
	for _, command := range []string{"ip", "wg"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("нет %s", command)
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	encoded := base64.StdEncoding.EncodeToString(key)

	root := t.TempDir()
	s := New(system.NewExec(), root)
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "wireguard", Installed: true}}
	ch := config.Channel{
		ID: "integration-wg", Index: 999, Name: "Integration WireGuard", Enabled: true,
		Type: "wireguard", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"address": "192.0.2.2/32", "private_key": encoded,
			"peer_public_key": encoded, "endpoint": "192.0.2.1:51820",
			"allowed_ips": []string{"0.0.0.0/0"},
		},
	}
	cfg.Channels = append(cfg.Channels, ch)
	defer s.removeChannel(context.Background(), ownedChannel{Name: InterfaceName(ch), Index: ch.Index})

	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	ch.Probe.FailThreshold = 1
	ch.Probe.RiseThreshold = 1
	state := &channelState{}
	s.record(context.Background(), cfg, ch, state, false)
	routes, _ := s.Runner.Run(context.Background(), "ip", "-4", "route", "show", "table", "1999")
	if strings.Contains(routes, "default dev wg-ch999") || !strings.Contains(routes, "blackhole default") {
		t.Fatalf("kill-switch table is unsafe:\n%s", routes)
	}
	s.record(context.Background(), cfg, ch, state, true)
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("channel did not recover: %v", err)
	}

	ch.FailMode = "direct"
	s.record(context.Background(), cfg, ch, &channelState{}, false)
	rules, _ := s.Runner.Run(context.Background(), "ip", "-4", "rule", "show")
	if strings.Contains(rules, "10999:") {
		t.Fatalf("direct fail mode kept channel rule:\n%s", rules)
	}
	if err := s.restoreChannel(context.Background(), ch); err != nil {
		t.Fatal(err)
	}

	backup := ch
	backup.ID = "backup"
	backup.Index = 998
	defer s.removeChannel(context.Background(), ownedChannel{Name: InterfaceName(backup), Index: backup.Index})
	cfg.Channels = append(cfg.Channels, backup)
	ch.FailMode = "fallback"
	ch.Fallback = "backup"
	s.record(context.Background(), cfg, ch, &channelState{}, false)
	rules, _ = s.Runner.Run(context.Background(), "ip", "-4", "rule", "show")
	if !strings.Contains(rules, "10999:") || !(strings.Contains(rules, "lookup 1998") || strings.Contains(rules, "lookup netos-ch998")) {
		t.Fatalf("fallback rule was not installed:\n%s", rules)
	}
	if err := s.restoreChannel(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	// Второе применение проверяет идемпотентный путь существующего интерфейса.
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationXrayLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	if _, err := os.Stat("/usr/local/bin/xray"); err != nil {
		t.Skip("xray is not installed")
	}
	root := t.TempDir()
	s := New(system.NewExec(), root)
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	ch := config.Channel{
		ID: "integration-xray", Index: 996, Name: "Integration Xray", Enabled: true,
		Type: "xray", Mode: "tun", FailMode: "block",
		Config: map[string]any{"mtu": 1380, "outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}}},
	}
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "xray", Installed: true}}
	cfg.Channels = append(cfg.Channels, ch)
	defer s.removeChannel(context.Background(), ownedChannel{Name: InterfaceName(ch), Index: ch.Index, Type: "xray", Unit: xrayUnitName(ch)})
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if out, err := s.Runner.Run(context.Background(), "systemctl", "is-active", xrayUnitName(ch)); err != nil || strings.TrimSpace(out) != "active" {
		t.Fatalf("Xray unit is not active: %q (%v)", out, err)
	}
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if s.linkExists(InterfaceName(ch)) {
		t.Fatal("Xray TUN interface was not removed")
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", xrayUnitName(ch))); !os.IsNotExist(err) {
		t.Fatalf("Xray unit was not removed: %v", err)
	}
}

func TestIntegrationOpenConnectLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	server, password := os.Getenv("NETOS_OC_SERVER"), os.Getenv("NETOS_OC_PASSWORD")
	if server == "" || password == "" {
		t.Skip("NETOS_OC_SERVER and NETOS_OC_PASSWORD are required")
	}
	if _, err := exec.LookPath("openconnect"); err != nil {
		t.Skip("openconnect is not installed")
	}
	root := t.TempDir()
	s := New(system.NewExec(), root)
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	ch := config.Channel{
		ID: "integration-oc", Index: 997, Name: "Integration OpenConnect", Enabled: true,
		Type: "openconnect", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"server": server, "username": "netos-test", "password": password,
			"protocol": "anyconnect", "servercert": os.Getenv("NETOS_OC_SERVERCERT"),
			"mtu": 1380, "no_system_trust": true,
		},
	}
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "openconnect", Installed: true}}
	cfg.Channels = append(cfg.Channels, ch)
	t.Cleanup(func() { _ = s.Apply(context.Background(), config.Default()) })
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	routes, _ := s.Runner.Run(context.Background(), "ip", "-4", "route", "show", "table", "1997")
	if !strings.Contains(routes, "default dev tun-ch997") || !strings.Contains(routes, "blackhole default") {
		t.Fatalf("incomplete OpenConnect routing table:\n%s", routes)
	}
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if s.linkExists("tun-ch997") {
		t.Fatal("OpenConnect interface remained after disable")
	}
}

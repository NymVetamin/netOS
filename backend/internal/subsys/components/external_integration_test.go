//go:build linux

package components

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/system"
)

// This test deliberately exercises the official release download as well as
// the real systemd/TUN lifecycle. It only runs explicitly on a disposable
// Linux integration host and restores the host to its original state.
func TestIntegrationXrayInstallAndLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	rel := externalReleases["xray"]
	if _, err := os.Stat(rel.Target); err == nil {
		t.Skipf("refusing to overwrite an existing %s", rel.Target)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}

	ctx := context.Background()
	componentSubsystem := New(system.NewExec(), quietLogger{})
	if err := componentSubsystem.installRelease(ctx, "xray", rel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(rel.Target) })
	if output, err := system.NewExec().Run(ctx, rel.Target, "version"); err != nil || !strings.Contains(output, "Xray") {
		t.Fatalf("installed Xray cannot run: %q (%v)", output, err)
	}

	// The service has PrivateTmp=true, so a config below testing.T's /tmp
	// directory is intentionally invisible to it.
	root, err := os.MkdirTemp("/var/lib", "netos-xray-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	channelSubsystem := channels.New(system.NewExec(), root)
	channelSubsystem.RTTablesPath = filepath.Join(root, "rt_tables")
	channel := config.Channel{
		ID: "integration-xray-install", Index: 996, Name: "Integration Xray", Enabled: true,
		Type: "xray", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"mtu":      1380,
			"outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}},
		},
	}
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "xray", Installed: true}}
	cfg.Channels = append(cfg.Channels, channel)
	t.Cleanup(func() { _ = channelSubsystem.Apply(context.Background(), config.Default()) })

	if err := channelSubsystem.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := channelSubsystem.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if output, err := system.NewExec().Run(ctx, "systemctl", "is-active", "netos-xray-ch996.service"); err != nil || strings.TrimSpace(output) != "active" {
		t.Fatalf("Xray service is not active: %q (%v)", output, err)
	}
	routes, err := system.NewExec().Run(ctx, "ip", "-4", "route", "show", "table", "1996")
	if err != nil || !strings.Contains(routes, "default dev tun-ch996") || !strings.Contains(routes, "blackhole default") {
		t.Fatalf("incomplete Xray routing table: %q (%v)", routes, err)
	}
	// Binding curl to the TUN proves that packets traverse Xray's userspace
	// stack and its outbound, rather than merely observing a created device.
	if output, err := system.NewExec().Run(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "15", "--interface", "tun-ch996", "https://1.1.1.1/cdn-cgi/trace"); err != nil || !strings.Contains(output, "ip=") {
		t.Fatalf("traffic did not pass through Xray TUN: %q (%v)", output, err)
	}

	if err := channelSubsystem.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", "netos-xray-ch996.service")); !os.IsNotExist(err) {
		t.Fatalf("Xray unit was not removed: %v", err)
	}
}

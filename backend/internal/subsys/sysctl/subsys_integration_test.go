//go:build linux

package sysctl

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationIPv6TogglesRealNamespacedKernel(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 и root")
	}
	if out, err := exec.Command("ip", "link", "add", "sysqa0", "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("dummy interface: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "sysqa0").Run() })

	oldPath := ipv6ConfPath
	ipv6ConfPath = filepath.Join(t.TempDir(), "99-netos-ipv6.conf")
	t.Cleanup(func() { ipv6ConfPath = oldPath })
	s := NewIPv6(&system.Exec{})
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.IPv6.Mode = "off"
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

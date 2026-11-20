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
	const name = "sysqa0.100"
	if out, err := exec.Command("ip", "link", "add", name, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("dummy interface: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })

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
	ra := filepath.Join("/proc/sys/net/ipv6/conf", name, "accept_ra")
	if err := os.WriteFile(ra, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("expected drift on dotted interface")
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(ra); err != nil || string(data) != "2\n" {
		t.Fatalf("accept_ra after repair = %q, %v", data, err)
	}
	cfg.IPv6.Mode = "off"
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

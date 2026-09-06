//go:build linux

package netiface

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

func TestIntegrationReport1953BondMTUAndMode(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	for _, name := range []string{"q1953p", "q1953peer", "q1953p2", "q1953peer2", "q1953bond"} {
		if linkExists(name) {
			t.Fatalf("existing link %s", name)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "q1953bond").Run()
		_ = exec.Command("ip", "link", "del", "q1953p").Run()
		_ = exec.Command("ip", "link", "del", "q1953p2").Run()
	})
	runner := system.NewExec()
	mustRunVPNStyle(t, runner, "ip", "link", "add", "q1953p", "type", "veth", "peer", "name", "q1953peer")
	mustRunVPNStyle(t, runner, "ip", "link", "add", "q1953p2", "type", "veth", "peer", "name", "q1953peer2")
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "p", Name: "q1953p", Type: "physical", Enabled: true, MTU: 1442},
		{ID: "p2", Name: "q1953p2", Type: "physical", Enabled: true, MTU: 1442},
		{ID: "b", Name: "q1953bond", Type: "bond", Enabled: true, MTU: 1400, Members: []string{"p", "p2"}},
	}
	s := NewInterfaces(runner)
	s.OwnedPath = filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(s.OwnedPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	// Bypass validation to reproduce the kernel behavior from the report.
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "MTU 1400 вместо 1442") {
		t.Fatalf("expected kernel MTU inheritance: %v", err)
	}
	if !cfg.Validate().HasErrors() {
		t.Fatal("incompatible MTU accepted before apply")
	}
	cfg.Interfaces[2].MTU = 1442
	if cfg.Validate().HasErrors() {
		t.Fatalf("matching MTU rejected: %+v", cfg.Validate())
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	assertSysfsValue(t, "/sys/class/net/q1953bond/bonding/mode", "balance-rr 0")
	// A bond left by the old boot renderer must be repaired immediately.
	mustRunVPNStyle(t, runner, "ip", "link", "set", "q1953p", "nomaster")
	mustRunVPNStyle(t, runner, "ip", "link", "set", "q1953p2", "nomaster")
	mustRunVPNStyle(t, runner, "ip", "link", "set", "q1953bond", "down")
	mustRunVPNStyle(t, runner, "ip", "link", "set", "q1953bond", "type", "bond", "mode", "802.3ad")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	assertSysfsValue(t, "/sys/class/net/q1953bond/bonding/mode", "balance-rr 0")
}

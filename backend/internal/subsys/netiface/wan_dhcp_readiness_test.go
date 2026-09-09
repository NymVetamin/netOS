package netiface

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type delayedLeaseRunner struct {
	wanApplyMatrixRunner
	polls      int
	readyAfter int
}

func (r *delayedLeaseRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "ip" && strings.Join(args, " ") == "-4 -o addr show dev eth-test" {
		r.polls++
		if r.readyAfter > 0 && r.polls >= r.readyAfter {
			return "2: eth-test inet 192.0.2.12/24 scope global eth-test\n", nil
		}
		return "", nil
	}
	return r.wanApplyMatrixRunner.Run(ctx, name, args...)
}
func (r *delayedLeaseRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestWANApplyWaitsForDHCPAddressBeforeDependentSubsystems(t *testing.T) {
	for _, tc := range []struct {
		name       string
		readyAfter int
		wantError  bool
	}{
		{"delayed address", 3, false}, {"stale marker without kernel address", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newFakeNet(t, "eth-test")
			root := t.TempDir()
			oldScripts, oldRuntime, oldUnits, oldConfs := dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir, pppoeConfDir
			dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir = filepath.Join(root, "generated"), filepath.Join(root, "run"), filepath.Join(root, "units")
			pppoeConfDir = dhcpScriptDir
			t.Cleanup(func() {
				dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir, pppoeConfDir = oldScripts, oldRuntime, oldUnits, oldConfs
			})
			for _, dir := range []string{dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dhcpRuntimeDir, "netos-dhcp-eth-test.address"), []byte("192.0.2.12/24\n"), 0600); err != nil {
				t.Fatal(err)
			}
			runner := &delayedLeaseRunner{wanApplyMatrixRunner: wanApplyMatrixRunner{active: map[string]bool{}}, readyAfter: tc.readyAfter}
			s := NewWAN(runner)
			s.OwnedAddressPath, s.OwnedRoutePath, s.OwnedLNSRoutePath = filepath.Join(root, "addresses.json"), filepath.Join(root, "routes.json"), filepath.Join(root, "lns.json")
			s.DHCPTimeout, s.DHCPPoll = 30*time.Millisecond, time.Millisecond
			cfg := config.Default()
			cfg.Interfaces = []config.Interface{{ID: "if-test", Name: "eth-test", Type: "physical", Enabled: true}}
			cfg.WANs = []config.WAN{{ID: "wan-test", Name: "Delayed DHCP", Interface: "if-test", Enabled: true, Proto: "dhcp", Metric: 200}}
			err := s.Apply(context.Background(), cfg)
			if tc.wantError {
				if err == nil {
					t.Fatal("Apply allowed dependent routing before the kernel received a DHCP address")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if runner.polls < tc.readyAfter {
					t.Fatalf("Apply returned before the DHCP address was ready: polls=%d", runner.polls)
				}
			}
		})
	}
}

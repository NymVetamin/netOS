package sysctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// networkdLinks imitates `networkctl list`: the link stays pending for a few
// queries, then networkd configures it and writes its own accept_ra=0.
type networkdLinks struct {
	pendingFor int
	calls      int
	err        error
	onConfig   func()
}

func (r *networkdLinks) Run(_ context.Context, name string, args ...string) (string, error) {
	if name != "networkctl" {
		return "", nil
	}
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	if r.calls <= r.pendingFor {
		return "  1 lo   loopback carrier  unmanaged\n  7 eth0.100 vlan off pending\n", nil
	}
	if r.calls == r.pendingFor+1 && r.onConfig != nil {
		r.onConfig()
	}
	// A link without carrier remains "configuring" for good.
	return "  1 lo   loopback carrier  unmanaged\n  7 eth0.100 vlan no-carrier configuring\n", nil
}

func (r *networkdLinks) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func passthroughLink(t *testing.T) (string, *config.Config) {
	t.Helper()
	withSysctlPaths(t)
	const name = "eth0.100"
	if err := os.MkdirAll(filepath.Join(netClassPath, name), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(procSysPath, "net", "ipv6", "conf", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	seedSysctls(t, NewIPv6(nil).values(cfg))
	for _, key := range ManagedPerInterfaceIPv6Keys() {
		if err := os.WriteFile(filepath.Join(dir, key), []byte("0"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "accept_ra"), cfg
}

func TestIPv6WritesAcceptRAAfterNetworkdConfiguresLink(t *testing.T) {
	ra, cfg := passthroughLink(t)
	runner := &networkdLinks{pendingFor: 2}
	runner.onConfig = func() {
		// networkd writes accept_ra=0 when it starts configuring the link.
		if err := os.WriteFile(ra, []byte("0"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := NewIPv6(runner)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(ra); string(data) != "2" {
		t.Fatalf("accept_ra = %q after networkd configured the link, want 2", data)
	}
	if runner.calls != 3 {
		t.Fatalf("networkctl queried %d times, want until the link left pending (3)", runner.calls)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestIPv6DoesNotWaitForConfiguringOrMissingNetworkd(t *testing.T) {
	_, cfg := passthroughLink(t)
	for _, runner := range []*networkdLinks{{}, {err: errors.New("networkd is not running")}} {
		start := time.Now()
		if err := NewIPv6(runner).Apply(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if runner.calls != 1 || time.Since(start) > time.Second {
			t.Fatalf("waited: %d queries, %v", runner.calls, time.Since(start))
		}
	}
}

func TestIPv6NetworkdWaitIsBounded(t *testing.T) {
	_, cfg := passthroughLink(t)
	old := networkdLinkWait
	networkdLinkWait = 300 * time.Millisecond
	t.Cleanup(func() { networkdLinkWait = old })
	start := time.Now()
	if err := NewIPv6(&networkdLinks{pendingFor: 1 << 30}).Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("wait not bounded: %v", elapsed)
	}
}

func TestIPv6PlanShowsResetInterfaceValue(t *testing.T) {
	ra, cfg := passthroughLink(t)
	s := NewIPv6(&networkdLinks{})
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.Plan(cfg, cfg); err != nil || len(actions) != 0 {
		t.Fatalf("applied state: %v, %v", actions, err)
	}
	// networkctl reconfigure resets accept_ra behind netOS's back.
	if err := os.WriteFile(ra, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.Plan(cfg, cfg); err != nil || len(actions) != 1 {
		t.Fatalf("reset accept_ra not planned: %v, %v", actions, err)
	}
}

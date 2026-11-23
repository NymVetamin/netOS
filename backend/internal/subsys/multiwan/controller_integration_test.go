//go:build linux

package multiwan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

const multiWANTestNS = "netos-mwtest"

func TestIntegrationRemovedWANStaysRemoved(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	if out, err := exec.Command("ip", "netns", "add", multiWANTestNS).CombinedOutput(); err != nil {
		t.Fatalf("netns: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", multiWANTestNS).Run() })
	mustNS(t, "ip", "link", "add", "wan0", "type", "dummy")
	mustNS(t, "ip", "link", "set", "wan0", "up")
	for _, operation := range []string{"apply", "tick"} {
		for _, state := range []string{"removed", "disabled", "enabled"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				mustNS(t, "ip", "route", "replace", "default", "dev", "wan0", "metric", "100")
				line := strings.TrimSpace(mustNS(t, "ip", "route", "show", "default"))
				mustNS(t, "ip", "route", "del", "default", "dev", "wan0", "metric", "100")
				c := New(namespaceRunner{}, t.TempDir(), integrationLogger{t})
				c.suppressed = map[string]string{"old": line}
				if err := c.save(); err != nil {
					t.Fatal(err)
				}
				cfg := config.Default()
				cfg.Interfaces = []config.Interface{{ID: "i", Name: "wan0"}}
				if state != "removed" {
					cfg.WANs = []config.WAN{{ID: "old", Interface: "i", Enabled: state == "enabled", Proto: "static"}}
				}
				for range 2 {
					if operation == "apply" {
						if err := c.Apply(context.Background(), cfg); err != nil {
							t.Fatal(err)
						}
					} else {
						c.tick(context.Background(), cfg)
					}
					out := mustNS(t, "ip", "route", "show", "default")
					if strings.Contains(out, "dev wan0") != (state == "enabled") {
						t.Fatalf("state=%s routes=%s", state, out)
					}
					if err := c.Health(context.Background(), cfg); err != nil {
						t.Fatal(err)
					}
				}
				t.Log("kernel default, persisted suppression cleanup, Health and repeat PASS")
			})
		}
	}
}

type namespaceRunner struct{}

func (namespaceRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	all := append([]string{"netns", "exec", multiWANTestNS, name}, args...)
	out, err := exec.Command("ip", all...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, out)
	}
	return string(out), nil
}

type integrationLogger struct{ t *testing.T }

func (l integrationLogger) Infof(f string, a ...any) { l.t.Logf(f, a...) }
func (l integrationLogger) Warnf(f string, a ...any) { l.t.Logf(f, a...) }
func (r namespaceRunner) RunInput(ctx context.Context, input string, name string, args ...string) (string, error) {
	all := append([]string{"netns", "exec", multiWANTestNS, name}, args...)
	cmd := exec.CommandContext(ctx, "ip", all...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, out)
	}
	return string(out), nil
}

func TestIntegrationFailoverRemovesAndRestoresRealRoute(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 и root")
	}
	_ = exec.Command("ip", "netns", "del", multiWANTestNS).Run()
	if out, err := exec.Command("ip", "netns", "add", multiWANTestNS).CombinedOutput(); err != nil {
		t.Fatalf("netns: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", multiWANTestNS).Run() })
	for _, name := range []string{"wan0", "wan1"} {
		mustNS(t, "ip", "link", "add", name, "type", "dummy")
		mustNS(t, "ip", "link", "set", name, "up")
	}
	mustNS(t, "ip", "route", "add", "default", "dev", "wan0", "metric", "100")
	mustNS(t, "ip", "route", "add", "default", "dev", "wan1", "metric", "200")

	healthy := false
	c := New(namespaceRunner{}, t.TempDir(), integrationLogger{t})
	c.Probe = func(context.Context, config.WAN, string) bool { return healthy }
	c.suppressed = map[string]string{}
	cfg := config.Default()
	cfg.MultiWAN.Enabled = true
	cfg.Interfaces = []config.Interface{{ID: "if0", Name: "wan0"}, {ID: "if1", Name: "wan1"}}
	cfg.WANs = []config.WAN{
		{ID: "primary", Name: "Primary", Interface: "if0", Enabled: true, Proto: "static", Probe: config.Probe{Enabled: true, Type: "icmp", Targets: []string{"192.0.2.1"}, Interval: 1, Timeout: 1, FailThreshold: 1, RiseThreshold: 1}},
		{ID: "backup", Name: "Backup", Interface: "if1", Enabled: true, Proto: "static", Probe: config.Probe{Enabled: false}},
	}
	c.tick(context.Background(), cfg)
	out := mustNS(t, "ip", "route", "show", "default")
	if strings.Contains(out, "dev wan0") || !strings.Contains(out, "dev wan1") {
		t.Fatalf("failover не сработал:\n%s", out)
	}
	t.Logf("сохранённый маршрут: %q", c.suppressed["primary"])
	healthy = true
	c.states["primary"].Next = time.Time{}
	c.tick(context.Background(), cfg)
	out = mustNS(t, "ip", "route", "show", "default")
	if !strings.Contains(out, "dev wan0") || !strings.Contains(out, "dev wan1") {
		t.Fatalf("маршрут не восстановлен:\n%s", out)
	}
}

func TestIntegrationPPPHistoryAfterInterfaceRecreation(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	for _, proto := range []string{"pppoe", "l2tp"} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/multiwan=%v", proto, enabled), func(t *testing.T) {
				mustHost(t, "ip", "netns", "add", multiWANTestNS)
				t.Cleanup(func() { exec.Command("ip", "netns", "del", multiWANTestNS).Run() })
				for _, dev := range []string{"eth1", "ppp-wan2"} {
					mustNS(t, "ip", "link", "add", dev, "type", "dummy")
					mustNS(t, "ip", "link", "set", dev, "up")
				}
				mustNS(t, "ip", "route", "add", "default", "dev", "eth1", "metric", "200")
				mustNS(t, "ip", "route", "add", "default", "dev", "ppp-wan2", "metric", "100")
				cfg := config.Default()
				cfg.MultiWAN.Enabled, cfg.MultiWAN.Mode = enabled, "failover"
				cfg.Interfaces = []config.Interface{{ID: "underlay", Name: "eth1", Type: "physical"}}
				cfg.WANs = []config.WAN{
					{ID: "wan1", Index: 1, Interface: "underlay", Enabled: true, Proto: "static", Metric: 200},
					{ID: "wan2", Index: 2, Enabled: true, Proto: proto, Metric: 100},
				}
				c := New(namespaceRunner{}, t.TempDir(), integrationLogger{t})
				if err := c.Apply(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				c.pausedUntil = time.Time{}
				for repeat := 0; repeat < 2; repeat++ {
					mustNS(t, "ip", "link", "del", "ppp-wan2")
					c.tick(context.Background(), cfg)
					mustNS(t, "ip", "link", "add", "ppp-wan2", "type", "dummy")
					mustNS(t, "ip", "link", "set", "ppp-wan2", "up")
					mustNS(t, "ip", "route", "add", "default", "dev", "ppp-wan2", "metric", "100")
					c.tick(context.Background(), cfg)
					out := mustNS(t, "ip", "route", "show", "table", "3002")
					if !strings.Contains(out, "default dev ppp-wan2") {
						t.Fatalf("client route not restored: %s", out)
					}
					if !strings.Contains(c.knownRoutes["wan2"], "ppp-wan2") {
						t.Fatalf("PPP history missing: %v", c.knownRoutes)
					}
					c.tick(context.Background(), cfg)
					if got := mustNS(t, "ip", "route", "show", "table", "3002"); got != out {
						t.Fatalf("unchanged tick changed routes: %s", got)
					}
				}
			})
		}
	}
}

// Run one flush without CAP_NET_ADMIN inside the test namespace. Snapshot
// reads, the rollback and the retry still use the normal privileged runner.
type deniedFlushRunner struct {
	namespaceRunner
	denied bool
}

func (r *deniedFlushRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !r.denied && name == "ip" && strings.Join(args, " ") == "-4 route flush table 3002" {
		r.denied = true
		return r.namespaceRunner.Run(ctx, "setpriv", append([]string{"--bounding-set=-net_admin", "ip"}, args...)...)
	}
	return r.namespaceRunner.Run(ctx, name, args...)
}

func TestIntegrationBalanceBuildsRealTablesAndRules(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 и root")
	}
	_ = exec.Command("ip", "netns", "del", multiWANTestNS).Run()
	mustHost(t, "ip", "netns", "add", multiWANTestNS)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", multiWANTestNS).Run() })
	for _, name := range []string{"wan0", "wan1"} {
		mustNS(t, "ip", "link", "add", name, "type", "dummy")
		mustNS(t, "ip", "link", "set", name, "up")
	}
	mustNS(t, "ip", "route", "add", "default", "dev", "wan0", "metric", "100")
	mustNS(t, "ip", "route", "add", "default", "dev", "wan1", "metric", "200")
	cfg := config.Default()
	cfg.MultiWAN.Enabled = true
	cfg.MultiWAN.Mode = "balance"
	cfg.Interfaces = []config.Interface{{ID: "if0", Name: "wan0"}, {ID: "if1", Name: "wan1"}}
	cfg.WANs = []config.WAN{{ID: "a", Index: 1, Name: "A", Interface: "if0", Enabled: true, Proto: "static", Weight: 1}, {ID: "b", Index: 2, Name: "B", Interface: "if1", Enabled: true, Proto: "static", Weight: 3}}
	c := New(namespaceRunner{}, t.TempDir(), integrationLogger{t})
	if err := c.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for table, dev := range map[string]string{"3001": "wan0", "3002": "wan1"} {
		out := mustNS(t, "ip", "route", "show", "table", table)
		if !strings.Contains(out, "default dev "+dev) || !strings.Contains(out, "blackhole default") {
			t.Fatalf("таблица %s:\n%s", table, out)
		}
	}
	rules := mustNS(t, "ip", "rule", "show")
	for _, want := range []string{"30001:", "fwmark 0x3001", "30002:", "fwmark 0x3002"} {
		if !strings.Contains(rules, want) {
			t.Fatalf("нет %s:\n%s", want, rules)
		}
	}
	// First-table edits must roll back if the kernel refuses to clear the second.
	for _, table := range []string{"3001", "3002"} {
		mustNS(t, "ip", "route", "add", "blackhole", "203.0.113.0/24", "table", table)
	}
	denied := &deniedFlushRunner{}
	c.Runner = denied
	if err := c.reconcileBalance(context.Background(), cfg); err == nil || !strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
		t.Fatalf("expected kernel flush refusal, got %v", err)
	}
	for _, table := range []string{"3001", "3002"} {
		if out := mustNS(t, "ip", "route", "show", "table", table); !strings.Contains(out, "blackhole 203.0.113.0/24") {
			t.Fatalf("rollback lost original route in table %s: %s", table, out)
		}
	}
	if err := c.reconcileBalance(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"3001", "3002"} {
		if out := mustNS(t, "ip", "route", "show", "table", table); strings.Contains(out, "203.0.113.0/24") {
			t.Fatalf("retry left stale route in table %s: %s", table, out)
		}
	}
	// A health-only failure keeps the selected table's original route for
	// established connmarks. The runtime classifier excludes it only for new
	// flows, avoiding a public-address change in an existing NAT session.
	c.states["a"] = &linkState{Down: true}
	if err := c.reconcileBalance(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	out := mustNS(t, "ip", "route", "show", "table", "3001")
	if !strings.Contains(out, "default dev wan0") || strings.Contains(out, "default dev wan1") {
		t.Fatalf("established flow was moved away from its live selected WAN:\n%s", out)
	}
	c.states["b"] = &linkState{Down: true}
	if err := c.reconcileBalance(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	out = mustNS(t, "ip", "route", "show", "table", "3001")
	if !strings.Contains(out, "default dev wan0") || !strings.Contains(out, "blackhole default") {
		t.Fatalf("selected table lost its own route or safety fallback:\n%s", out)
	}
	// A failed health target does not make the public management address
	// unreachable: locally sourced replies keep the incoming WAN's table.
	mustNS(t, "ip", "addr", "add", "192.0.2.2/24", "dev", "wan0")
	cfg.MultiWAN.Mode = "failover"
	if err := c.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	mustNS(t, "ip", "route", "del", "default", "dev", "wan0")
	out = mustNS(t, "ip", "route", "get", "198.51.100.1", "from", "192.0.2.2")
	if !strings.Contains(out, "dev wan0") {
		t.Fatalf("management reply escaped through backup: %s", out)
	}
	if err := c.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if out := mustNS(t, "ip", "rule", "show"); strings.Contains(out, "30001:") || strings.Contains(out, "30002:") {
		t.Fatalf("source/probe rules survived disabling Multi-WAN: %s", out)
	}
}

func mustHost(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v %s", name, err, out)
	}
}

func mustNS(t *testing.T, name string, args ...string) string {
	t.Helper()
	all := append([]string{"netns", "exec", multiWANTestNS, name}, args...)
	out, err := exec.Command("ip", all...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(all, " "), err, out)
	}
	return string(out)
}

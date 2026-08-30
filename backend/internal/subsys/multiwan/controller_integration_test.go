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
func (r namespaceRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
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
	// A failed uplink must keep established marked flows usable through the
	// healthy fallback table. If every uplink is down, the blackhole remains
	// and traffic must not leak through the main table.
	c.states["a"] = &linkState{Down: true}
	if err := c.reconcileBalance(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	out := mustNS(t, "ip", "route", "show", "table", "3001")
	if !strings.Contains(out, "default dev wan1") {
		t.Fatalf("failed uplink did not switch to the fallback:\n%s", out)
	}
	c.states["b"] = &linkState{Down: true}
	if err := c.reconcileBalance(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	out = mustNS(t, "ip", "route", "show", "table", "3001")
	if strings.Contains(out, "default dev") || !strings.Contains(out, "blackhole default") {
		t.Fatalf("all-down table can leak traffic:\n%s", out)
	}
	if err := c.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
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

//go:build linux

package routing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

const routingTestNS = "netos-rttest"

type routingNamespaceRunner struct{}

func (routingNamespaceRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	all := append([]string{"netns", "exec", routingTestNS, name}, args...)
	out, err := exec.Command("ip", all...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, out)
	}
	return string(out), nil
}

func (r routingNamespaceRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestIntegrationReconcilesKernelRoutesAndRules(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 и root")
	}
	_ = exec.Command("ip", "netns", "del", routingTestNS).Run()
	mustRoutingHost(t, "ip", "netns", "add", routingTestNS)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", routingTestNS).Run() })

	s := New(routingNamespaceRunner{})
	cfg := config.Default()
	cfg.Routing.Static = []config.StaticRoute{
		{Enabled: true, Destination: "10.77.0.0/16", Type: "blackhole", Table: "200", Metric: 7},
		{Enabled: true, Destination: "2001:db8:77::/48", Type: "unreachable", Table: "200", Metric: 9},
	}
	cfg.Routing.Rules = []config.RouteRule{{Enabled: true, Name: "qa", Priority: 20123, From: "192.0.2.0/24", Table: "200"}}
	if err := s.applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.applyRules(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	v4 := mustRoutingNS(t, "ip", "-4", "route", "show", "table", "200")
	v6 := mustRoutingNS(t, "ip", "-6", "route", "show", "table", "200")
	rules := mustRoutingNS(t, "ip", "-4", "rule", "show")
	for output, want := range map[string]string{v4: "blackhole 10.77.0.0/16", v6: "unreachable 2001:db8:77::/48", rules: "20123:"} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q in:\n%s", want, output)
		}
	}

	clean := config.Default()
	if err := s.applyRoutes(context.Background(), clean); err != nil {
		t.Fatal(err)
	}
	if err := s.applyRules(context.Background(), clean); err != nil {
		t.Fatal(err)
	}
	if out := mustRoutingNS(t, "ip", "-4", "route", "show", "table", "200"); strings.TrimSpace(out) != "" {
		t.Fatalf("IPv4 route remained after cleanup: %s", out)
	}
	if out := mustRoutingNS(t, "ip", "-6", "route", "show", "table", "200"); strings.TrimSpace(out) != "" {
		t.Fatalf("IPv6 route remained after cleanup: %s", out)
	}
	if out := mustRoutingNS(t, "ip", "-4", "rule", "show"); strings.Contains(out, "20123:") {
		t.Fatalf("rule remained after cleanup: %s", out)
	}
}

func mustRoutingHost(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func mustRoutingNS(t *testing.T, name string, args ...string) string {
	t.Helper()
	return mustRoutingHost(t, "ip", append([]string{"netns", "exec", routingTestNS, name}, args...)...)
}

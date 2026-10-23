//go:build linux

package routing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

const routingTestNS = "netos-rttest"

type routingNamespaceRunner struct{}

type routingCountingRunner struct {
	routingNamespaceRunner
	mutations      int
	routeMutations int
}

func (r *routingCountingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if len(args) > 2 && args[1] == "route" && (args[2] == "replace" || args[2] == "del") {
		r.routeMutations++
	}
	if len(args) > 2 && args[1] == "rule" && (args[2] == "add" || args[2] == "del") {
		r.mutations++
	}
	return r.routingNamespaceRunner.Run(ctx, name, args...)
}

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
	counted := &routingCountingRunner{}
	t.Log("IPv4 before repeat:", mustRoutingNS(t, "ip", "-4", "route", "show", "table", "all", "proto", "static"))
	t.Log("IPv6 before repeat:", mustRoutingNS(t, "ip", "-6", "route", "show", "table", "all", "proto", "static"))
	s.Runner = counted
	renamed := *cfg
	renamed.Routing.Static = append([]config.StaticRoute(nil), cfg.Routing.Static...)
	renamed.Routing.Rules = append([]config.RouteRule(nil), cfg.Routing.Rules...)
	renamed.Routing.Static[0].Name = "renamed IPv4 route"
	renamed.Routing.Static[1].Name = "renamed IPv6 route"
	renamed.Routing.Rules[0].Name = "renamed rule"
	for _, pair := range [][2]*config.Config{{cfg, &renamed}, {&renamed, cfg}} {
		actions, err := s.Plan(pair[0], pair[1])
		if err != nil || len(actions) != 2 {
			t.Fatalf("name plan: %v %v", actions, err)
		}
		for _, action := range actions {
			if action.Disruptive || action.Confirmation != apply.ConfirmationSafe {
				t.Fatalf("name edit requires confirmation: %v", actions)
			}
		}
		for i := 0; i < 2; i++ {
			if err := s.applyRoutes(context.Background(), pair[1]); err != nil {
				t.Fatal(err)
			}
			if err := s.applyRules(context.Background(), pair[1]); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(context.Background(), pair[1]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if counted.routeMutations != 0 || counted.mutations != 0 {
		t.Fatal("name edits mutated kernel routing")
	}
	if err := s.applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if counted.routeMutations != 0 {
		t.Fatalf("unchanged routes rewritten: %d", counted.routeMutations)
	}
	mustRoutingNS(t, "ip", "-4", "route", "del", "blackhole", "10.77.0.0/16", "table", "200", "metric", "7")
	if err := s.applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if counted.routeMutations != 1 {
		t.Fatalf("missing route not restored: %d", counted.routeMutations)
	}
	if err := s.applyRules(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if counted.mutations != 0 {
		t.Fatalf("unchanged kernel rules recreated: %d", counted.mutations)
	}
	mustRoutingNS(t, "ip", "-4", "rule", "del", "priority", "20123")
	if err := s.applyRules(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if counted.mutations != 1 {
		t.Fatalf("missing rule not restored: %d", counted.mutations)
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
	emptyTable := *cfg
	emptyTable.Routing.Tables = []config.RouteTable{{Name: "qa-empty", Number: 209}}
	for _, pair := range [][2]*config.Config{{cfg, &emptyTable}, {&emptyTable, cfg}} {
		actions, err := s.Plan(pair[0], pair[1])
		if err != nil || len(actions) != 1 || actions[0].Confirmation != apply.ConfirmationSafe {
			t.Fatalf("unused table plan: %v %v", actions, err)
		}
	}
	mustRoutingNS(t, "ip", "-6", "route", "add", "unreachable", "2001:db8:209::/48", "table", "209")
	actions, err := s.Plan(cfg, &emptyTable)
	if err != nil || len(actions) != 1 || actions[0].Confirmation == apply.ConfirmationSafe {
		t.Fatalf("live IPv6 table use ignored: %v %v", actions, err)
	}
	mustRoutingNS(t, "ip", "-6", "route", "del", "unreachable", "2001:db8:209::/48", "table", "209")
	mustRoutingNS(t, "ip", "-4", "rule", "add", "priority", "12345", "lookup", "209")
	actions, err = s.Plan(cfg, &emptyTable)
	if err != nil || len(actions) != 1 || actions[0].Confirmation == apply.ConfirmationSafe {
		t.Fatalf("foreign rule table use ignored: %v %v", actions, err)
	}
	mustRoutingNS(t, "ip", "-4", "rule", "del", "priority", "12345")

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

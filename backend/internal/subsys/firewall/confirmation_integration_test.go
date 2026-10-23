//go:build linux

package firewall

import (
	"context"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationAnnotationConfirmation(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and NETOS_INTEGRATION=1 in isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == init {
		t.Fatal("refusing to modify host network namespace")
	}
	ctx := context.Background()
	runner := system.NewExec()
	s := New(runner, t.TempDir())
	old, _ := configuredFirewall(t)
	old.Clients = []config.Client{{ID: "routed", Name: "Before", MAC: "02:00:00:00:00:02", Channel: "direct"}, {ID: "blocked", Name: "Before", MAC: "02:00:00:00:00:03", Blocked: true}}
	old.Policies = []config.Policy{{ID: "named", Name: "Before", Enabled: true, SrcIP: "192.0.2.8", Channel: "direct"}}
	old.Firewall.Rules = []config.FirewallRule{{ID: "annotation", Name: "before", Enabled: true, Zone: "lan", Flow: "forward", Action: "accept"}}
	if err := s.Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	for _, logging := range []bool{true, false} {
		next := *old
		next.Clients = append([]config.Client(nil), old.Clients...)
		for i := range next.Clients {
			if logging {
				next.Clients[i].Name = "After"
			} else {
				next.Clients[i].Name = "Before"
			}
		}
		next.Policies = append([]config.Policy(nil), old.Policies...)
		next.Policies[0].Name = "After"
		next.Firewall.Rules = append([]config.FirewallRule(nil), old.Firewall.Rules...)
		next.Firewall.Rules[0].Name = "after"
		next.Firewall.Rules[0].Log = logging
		actions, err := s.Plan(old, &next)
		if err != nil {
			t.Fatal(err)
		}
		if len(actions) == 0 {
			t.Fatal("missing action")
		}
		for i := range actions {
			actions[i].Subsystem = s.Name()
		}
		if apply.NeedsConfirmation(actions) {
			t.Fatalf("annotation change requires confirmation: %+v", actions)
		}
		if err := s.Apply(ctx, &next); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, &next); err != nil {
			t.Fatal(err)
		}
		if err := s.Apply(ctx, &next); err != nil {
			t.Fatal(err)
		}
		if actions, err := s.Plan(&next, &next); err != nil || len(actions) != 0 {
			t.Fatalf("repeat actions=%+v err=%v", actions, err)
		}
		old = &next
	}
	if _, err := runner.Run(ctx, "iptables", "-A", "INPUT", "-s", "198.51.100.9", "-j", "DROP"); err != nil {
		t.Fatal(err)
	}
	next := *old
	next.Firewall.Rules = append([]config.FirewallRule(nil), old.Firewall.Rules...)
	next.Firewall.Rules[0].Name = "third"
	actions, err := s.Plan(old, &next)
	if err != nil {
		t.Fatal(err)
	}
	for i := range actions {
		actions[i].Subsystem = s.Name()
	}
	if !apply.NeedsConfirmation(actions) {
		t.Fatal("live drift lost confirmation")
	}
	if err := s.Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, old); err != nil {
		t.Fatal(err)
	}
}

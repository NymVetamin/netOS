package policy

import (
	"context"
	"slices"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Inspect the live set after each individual mutation, including a failed
// batch. Checking just the final state misses an empty interval during rollback.
type observedStaticSets struct {
	system.Runner
	t     *testing.T
	names []string
}

func (r *observedStaticSets) check(ctx context.Context) {
	r.t.Helper()
	for _, name := range r.names {
		detail, err := r.Runner.Run(ctx, "ipset", "list", name)
		if err != nil || !slices.Contains(setMembers(detail), "192.0.2.1/32") {
			r.t.Fatalf("live member lost in %s: %s (%v)", name, detail, err)
		}
	}
}
func (r *observedStaticSets) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := r.Runner.Run(ctx, name, args...)
	if name == "ipset" && len(args) > 0 && args[0] != "list" && args[0] != "save" {
		r.check(ctx)
	}
	return out, err
}
func (r *observedStaticSets) RunInput(ctx context.Context, input, name string, args ...string) (string, error) {
	out, err := r.Runner.RunInput(ctx, input, name, args...)
	r.check(ctx)
	return out, err
}
func TestStaticSetRollbackMembership(t *testing.T) {
	testStaticSetRollbackMembership(t, newPolicyRunner())
}
func testStaticSetRollbackMembership(t *testing.T, base system.Runner) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Firewall.IPSets = []config.FirewallIPSet{{ID: "atomic-a", Entries: []string{"192.0.2.1", "192.0.2.2"}}, {ID: "atomic-b", Entries: []string{"192.0.2.1", "192.0.2.2"}}}
	r := &observedStaticSets{Runner: base, t: t}
	s := New(r, t.TempDir())
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	old := *cfg
	old.Firewall.IPSets = slices.Clone(cfg.Firewall.IPSets)
	for i := range cfg.Firewall.IPSets {
		r.names = append(r.names, FirewallSetName(cfg.Firewall.IPSets[i].ID))
		cfg.Firewall.IPSets[i].Entries = []string{"192.0.2.1", "192.0.2.3"}
	}
	slices.Sort(r.names)
	for _, name := range r.names {
		rule := []string{"INPUT", "-m", "set", "--match-set", name, "src", "-j", "DROP"}
		if _, err := base.Run(ctx, "iptables", append([]string{"-A"}, rule...)...); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := base.Run(ctx, "iptables", append([]string{"-D"}, rule...)...); err != nil {
				t.Error(err)
			}
		})
	}
	for _, name := range r.names {
		temp := name + "-next"
		if _, err := base.Run(ctx, "ipset", "create", temp, "hash:net", "family", "inet", "maxelem", "65536"); err != nil {
			t.Fatal(err)
		}
		if err := s.Apply(ctx, cfg); err == nil {
			t.Fatal("expected staging conflict")
		}
		if err := s.Health(ctx, &old); err != nil {
			t.Fatalf("rollback of %s: %v", name, err)
		}
		if _, err := base.Run(ctx, "ipset", "destroy", temp); err != nil {
			t.Fatal("foreign set lost:", err)
		}
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}

package policy

import (
	"context"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestFirewallSetUpdateRollbackAndOwnership(t *testing.T) {
	ctx := context.Background()
	r := newPolicyRunner()
	s := New(r, t.TempDir())
	cfg := config.Default()
	cfg.Firewall.IPSets = []config.FirewallIPSet{{ID: "deny", Name: "Denied", Entries: []string{"192.0.2.10", "198.51.100.5/24"}}}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	name := FirewallSetName("deny")
	r.inUse[name] = true
	before := append([]string(nil), r.sets[name].entries...)
	cfg.Firewall.IPSets[0].Entries = []string{"203.0.113.10"}
	r.failContains = "swap "
	if err := s.Apply(ctx, cfg); err == nil {
		t.Fatal("injected failure ignored")
	}
	if !reflect.DeepEqual(before, r.sets[name].entries) {
		t.Fatal("failed edit lost old entries")
	}
	if _, ok := r.sets[name+"-next"]; ok {
		t.Fatal("temporary set leaked")
	}
	r.failContains = ""
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	r.sets[name] = fakeSet{kind: "hash:net", family: "inet", entries: []string{"192.0.2.99"}}
	if err := s.Health(ctx, cfg); err == nil {
		t.Fatal("membership drift ignored")
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	r.inUse[name] = false
	cfg.Firewall.IPSets = nil
	if err := NewCleanup(r, s.StateDir).Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if len(r.sets) != 0 {
		t.Fatal("deleted set remains")
	}
	r.sets[name] = fakeSet{kind: "hash:net", family: "inet"}
	cfg.Firewall.IPSets = []config.FirewallIPSet{{ID: "deny", Name: "Denied"}}
	if err := s.Apply(ctx, cfg); err == nil {
		t.Fatal("foreign set adopted")
	}
}

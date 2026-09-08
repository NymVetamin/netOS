package policy

import (
	"context"
	"strings"
	"testing"
)

func TestDomainChangePreservesReferencedSetAndRollsBackEntries(t *testing.T) {
	for _, failLater := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "rollback"}[failLater], func(t *testing.T) {
			r := newPolicyRunner()
			s := New(r, t.TempDir())
			cfg := domainPolicyConfig("domains")
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			name := IPv4SetName("domains")
			set := r.sets[name]
			set.entries = []string{"192.0.2.1"}
			r.sets[name] = set
			r.inUse[name] = true
			r.commands = nil
			cfg.Policies[0].Domains = []string{"changed.example"}
			if failLater {
				cfg.Policies = append(cfg.Policies, domainPolicyConfig("later").Policies[0])
				r.failContains = "create " + IPv4SetName("later")
			}
			err := s.Apply(context.Background(), cfg)
			if failLater {
				if err == nil || !strings.Contains(err.Error(), "injected") || strings.Contains(err.Error(), "rollback") {
					t.Fatalf("expected original failure with successful rollback, got %v", err)
				}
				if got := r.sets[name].entries; len(got) != 1 || got[0] != "192.0.2.1" {
					t.Fatalf("lost learned entries: %v", got)
				}
				owned, err := s.readOwned()
				if err != nil || len(owned) != 1 || owned[0].Definition != desiredSets(domainPolicyConfig("domains"))[0].Definition {
					t.Fatalf("ownership not restored: %+v, %v", owned, err)
				}
			} else if err != nil || len(r.sets[name].entries) != 0 {
				t.Fatalf("domain change did not clear previous addresses: %v, %+v", err, r.sets[name])
			}
			if !strings.Contains(strings.Join(r.commands, "\n"), "ipset flush "+name) {
				t.Fatal("test did not reach the referenced set update")
			}
			for _, command := range r.commands {
				if command == "ipset destroy "+name || strings.HasPrefix(command, "ipset create "+name+" ") {
					t.Fatalf("recreated referenced set: %s", command)
				}
			}
		})
	}
}

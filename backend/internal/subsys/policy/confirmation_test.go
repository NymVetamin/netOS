package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

type referenceRunner struct {
	*policyRunner
	references string
}

func (r referenceRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := r.policyRunner.Run(ctx, name, args...)
	if name == "ipset" && len(args) == 2 && args[0] == "list" && args[1] != "-name" {
		out = strings.Replace(out, "Members:", r.references+"\nMembers:", 1)
	}
	return out, err
}

func TestUnusedStaticSetConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		refs        string
		used, drift bool
		safe        bool
	}{
		{"unused", "References: 0", false, false, true},
		{"kernel reference", "References: 1", false, false, false},
		{"unknown references", "", false, false, false},
		{"enabled rule", "References: 0", true, false, false},
		{"missing live set", "References: 0", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := referenceRunner{newPolicyRunner(), tc.refs}
			s := New(r, t.TempDir())
			old := config.Default()
			old.Firewall.IPSets = []config.FirewallIPSet{{ID: "stored", Entries: []string{"192.0.2.1"}}}
			if tc.used {
				old.Firewall.Rules = append(old.Firewall.Rules, config.FirewallRule{Enabled: true, SrcIPSet: "stored"})
			}
			if err := s.Apply(context.Background(), old); err != nil {
				t.Fatal(err)
			}
			if tc.drift {
				delete(r.sets, FirewallSetName("stored"))
			}
			next := *old
			next.Firewall.IPSets = []config.FirewallIPSet{{ID: "stored", Entries: []string{"192.0.2.2"}}}
			actions, err := s.Plan(old, &next)
			if err != nil || len(actions) != 1 {
				t.Fatalf("plan: %v %v", actions, err)
			}
			if got := actions[0].Confirmation == apply.ConfirmationSafe; got != tc.safe {
				t.Fatalf("safe=%v want %v: %v", got, tc.safe, actions)
			}
		})
	}
}

func TestUnchangedDomainSetsConfirmation(t *testing.T) {
	for _, scenario := range []string{"channel", "priority", "domains", "missing", "read failure"} {
		t.Run(scenario, func(t *testing.T) {
			r := newPolicyRunner()
			s := New(r, t.TempDir())
			old := domainPolicyConfig("domains")
			if err := s.Apply(context.Background(), old); err != nil {
				t.Fatal(err)
			}
			next := *old
			next.Policies = append([]config.Policy(nil), old.Policies...)
			next.Policies[0].Channel = "other"
			safe := scenario == "channel" || scenario == "priority"
			switch scenario {
			case "priority":
				next.Policies[0].Priority++
			case "domains":
				next.Policies[0].Domains = []string{"changed.example"}
			case "missing":
				delete(r.sets, IPv4SetName("domains"))
			case "read failure":
				r.failContains = "ipset list"
			}
			actions, err := s.Plan(old, &next)
			if err != nil || len(actions) != 1 {
				t.Fatalf("plan: %v %v", actions, err)
			}
			actions[0].Subsystem = "policy"
			if got := !apply.NeedsConfirmation(actions); got != safe {
				t.Fatalf("safe=%v want %v: %v", got, safe, actions)
			}
			mixed := append(actions, apply.Action{Subsystem: "firewall", Confirmation: apply.ConfirmationRequired})
			if !apply.NeedsConfirmation(mixed) {
				t.Fatal("policy exemption masked risky firewall action")
			}
		})
	}
}

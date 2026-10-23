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

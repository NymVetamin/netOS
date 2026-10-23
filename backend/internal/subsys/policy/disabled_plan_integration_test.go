//go:build linux

package policy

import (
	"context"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationDisabledPolicyPreservesActiveSet(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and isolated network namespace")
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
		t.Fatal("refusing host network namespace")
	}
	r := system.NewExec()
	ctx := context.Background()
	// This test must never install packages on the host.
	if _, err := r.Run(ctx, "dpkg-query", "-W", "ipset"); err != nil {
		t.Fatal("ipset must already be installed")
	}
	s := New(r, t.TempDir())
	base := domainPolicyConfig("active")
	if err := s.Apply(ctx, base); err != nil {
		t.Fatal(err)
	}
	name := IPv4SetName("active")
	if _, err := r.Run(ctx, "ipset", "add", name, "192.0.2.5"); err != nil {
		t.Fatal(err)
	}
	stored := *base
	stored.Firewall.IPSets = []config.FirewallIPSet{{ID: "unused", Entries: []string{"192.0.2.10"}}}
	edited := stored
	edited.Firewall.IPSets = []config.FirewallIPSet{{ID: "unused", Entries: []string{"192.0.2.11"}}}
	cleanup := NewCleanup(r, s.StateDir)
	for _, pair := range [][2]*config.Config{{base, &stored}, {&stored, &edited}, {&edited, base}} {
		actions, err := s.Plan(pair[0], pair[1])
		if err != nil || len(actions) != 1 || actions[0].Confirmation != apply.ConfirmationSafe {
			t.Fatalf("unused static set plan: %v %v", actions, err)
		}
		if err := s.Apply(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		if err := cleanup.Apply(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		if err := s.Apply(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Run(ctx, "ipset", "test", name, "192.0.2.5"); err != nil {
			t.Fatal("unrelated learned domain address lost", err)
		}
		if len(pair[1].Firewall.IPSets) > 0 {
			set := FirewallSetName("unused")
			entry := pair[1].Firewall.IPSets[0].Entries[0]
			if _, err := r.Run(ctx, "ipset", "test", set, entry); err != nil {
				t.Fatal(err)
			}
			args := []string{"INPUT", "-m", "set", "--match-set", set, "src", "-j", "ACCEPT"}
			if _, err := r.Run(ctx, "iptables", append([]string{"-A"}, args...)...); err != nil {
				t.Fatal(err)
			}
			risky, err := s.Plan(pair[1], base)
			if err != nil || len(risky) != 1 || risky[0].Confirmation == apply.ConfirmationSafe {
				t.Fatalf("foreign kernel rule not protected: %v %v", risky, err)
			}
			if _, err := r.Run(ctx, "iptables", append([]string{"-D"}, args...)...); err != nil {
				t.Fatal(err)
			}
		}
	}
	next := *base
	next.Policies = append(append([]config.Policy(nil), base.Policies...), config.Policy{ID: "disabled", Domains: []string{"disabled.example"}, Channel: "direct"})
	next.Policies[0].Name = "Renamed policy"
	next.Policies[0].Comment = "Updated description"
	for _, pair := range [][2]*config.Config{{base, &next}, {&next, &next}, {&next, base}} {
		if actions, err := s.Plan(pair[0], pair[1]); err != nil || len(actions) != 0 {
			t.Fatalf("plan=%+v err=%v", actions, err)
		}
		if err := s.Apply(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Run(ctx, "ipset", "test", name, "192.0.2.5"); err != nil {
			t.Fatalf("learned entry lost: %v", err)
		}
	}
	changed := *base
	changed.Policies = append([]config.Policy(nil), base.Policies...)
	changed.Policies[0].Channel = "another-channel"
	changed.Policies[0].Priority++
	for _, pair := range [][2]*config.Config{{base, &changed}, {&changed, base}} {
		actions, err := s.Plan(pair[0], pair[1])
		if err != nil || len(actions) != 1 || actions[0].Confirmation != apply.ConfirmationSafe {
			t.Fatalf("unchanged domain sets: %v %v", actions, err)
		}
		for i := 0; i < 2; i++ {
			if err := s.Apply(ctx, pair[1]); err != nil {
				t.Fatal(err)
			}
			if err := cleanup.Apply(ctx, pair[1]); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(ctx, pair[1]); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Run(ctx, "ipset", "test", name, "192.0.2.5"); err != nil {
				t.Fatalf("channel change lost learned entry: %v", err)
			}
		}
	}
	if _, err := r.Run(ctx, "ipset", "destroy", name); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.Plan(base, &next); err != nil || len(actions) != 1 || actions[0].Kind != "repair" {
		t.Fatalf("repair=%+v err=%v", actions, err)
	}
	if err := s.Apply(ctx, &next); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, &next); err != nil {
		t.Fatal(err)
	}
}

//go:build linux

package policy

import (
	"context"
	"os"
	"testing"

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
	next := *base
	next.Policies = append(append([]config.Policy(nil), base.Policies...), config.Policy{ID: "disabled", Domains: []string{"disabled.example"}, Channel: "direct"})
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

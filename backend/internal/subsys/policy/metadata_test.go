package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestPolicySubsystemMetadataAndLegacyFamilyNames(t *testing.T) {
	primary := New(nil, t.TempDir())
	cleanup := NewCleanup(nil, t.TempDir())
	if primary.Name() != "policy" || cleanup.Name() != "policy-cleanup" {
		t.Fatalf("names primary=%q cleanup=%q", primary.Name(), cleanup.Name())
	}
	if IPv4SetName("policy-a") == IPv6SetName("policy-a") {
		t.Fatal("IPv4 and legacy IPv6 ownership names collide")
	}
	if actions, err := cleanup.Plan(config.Default(), config.Default()); err != nil || len(actions) != 0 {
		t.Fatalf("cleanup plan=%v err=%v", actions, err)
	}
	if err := cleanup.Health(context.Background(), config.Default()); err != nil {
		t.Fatalf("cleanup health=%v", err)
	}
}

func TestPolicyPlanCreateUpdateDeleteAndRepair(t *testing.T) {
	runner := newPolicyRunner()
	s := New(runner, t.TempDir())
	empty := config.Default()
	first := domainPolicyConfig("domains")
	changed := domainPolicyConfig("domains")
	changed.Policies[0].Domains = []string{"changed.example"}

	tests := []struct {
		name      string
		old, next *config.Config
		kind      string
	}{
		{"create", empty, first, "create"},
		{"update", first, changed, "update"},
		{"delete", first, empty, "delete"},
	}
	for _, tc := range tests {
		actions, err := s.Plan(tc.old, tc.next)
		if err != nil || len(actions) != 1 || actions[0].Kind != tc.kind {
			t.Fatalf("%s plan=%#v err=%v", tc.name, actions, err)
		}
		if strings.Contains(actions[0].Detail, "IPv6") || !strings.Contains(actions[0].Detail, "IPv4") {
			t.Fatalf("%s misleading detail=%q", tc.name, actions[0].Detail)
		}
	}

	if err := s.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	set := runner.sets[IPv4SetName("domains")]
	set.timeout++
	runner.sets[IPv4SetName("domains")] = set
	actions, err := s.Plan(first, first)
	if err != nil || len(actions) != 1 || actions[0].Kind != "repair" {
		t.Fatalf("repair plan=%#v err=%v", actions, err)
	}
}

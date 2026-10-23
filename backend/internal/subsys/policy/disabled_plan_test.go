package policy

import (
	"context"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestDisabledDomainPolicyDoesNotPlanRuntimeChange(t *testing.T) {
	r := newPolicyRunner()
	s := New(r, t.TempDir())
	base := domainPolicyConfig("active")
	if err := s.Apply(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	next := *base
	next.Policies = append(append([]config.Policy(nil), base.Policies...), config.Policy{ID: "disabled", Enabled: false, Domains: []string{"disabled.example"}, Channel: "direct"})
	for _, pair := range [][2]*config.Config{{base, &next}, {&next, base}} {
		if actions, err := s.Plan(pair[0], pair[1]); err != nil || len(actions) != 0 {
			t.Fatalf("disabled policy plan=%+v err=%v", actions, err)
		}
	}
	edited := next
	edited.Policies = append([]config.Policy(nil), next.Policies...)
	edited.Policies[1].Domains = []string{"changed.example"}
	if actions, err := s.Plan(&next, &edited); err != nil || len(actions) != 0 {
		t.Fatalf("disabled edit plan=%+v err=%v", actions, err)
	}
	edited.Policies[1].Enabled = true
	if actions, err := s.Plan(&next, &edited); err != nil || len(actions) == 0 {
		t.Fatalf("enable plan=%+v err=%v", actions, err)
	}
	edited.Policies[1].Enabled = false
	delete(r.sets, IPv4SetName("active"))
	if actions, err := s.Plan(&next, &edited); err != nil || len(actions) != 1 || actions[0].Kind != "repair" {
		t.Fatalf("repair hidden by disabled edit: %+v %v", actions, err)
	}
}

func TestPolicyDescriptionDoesNotPlanSetChange(t *testing.T) {
	s := New(newPolicyRunner(), t.TempDir())
	old := domainPolicyConfig("active")
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := *old
	next.Policies = append([]config.Policy(nil), old.Policies...)
	next.Policies[0].Name = "New display name"
	next.Policies[0].Comment = "New comment"
	if actions, err := s.Plan(old, &next); err != nil || len(actions) != 0 {
		t.Fatalf("description created runtime action: %v %v", actions, err)
	}
	next.Policies[0].Domains = []string{"different.example"}
	if actions, err := s.Plan(old, &next); err != nil || len(actions) == 0 {
		t.Fatalf("domain change lost: %v %v", actions, err)
	}
}

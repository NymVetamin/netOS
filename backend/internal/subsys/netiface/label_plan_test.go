package netiface

import (
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestInterfaceLabelDoesNotPlanNetworkChange(t *testing.T) {
	old := config.Default()
	old.Interfaces = []config.Interface{{ID: "port", Name: "qa-label-port", Type: "physical", Enabled: true, Label: "before", MTU: 1500}}
	next := *old
	next.Interfaces = append([]config.Interface(nil), old.Interfaces...)
	next.Interfaces[0].Label = "after"
	s := NewInterfaces(nil)
	s.OwnedPath = filepath.Join(t.TempDir(), "owned")
	actions, err := s.Plan(old, &next)
	if err != nil || len(actions) != 0 {
		t.Fatalf("display label planned a network change: %v %v", actions, err)
	}
	if old.Interfaces[0].Label != "before" || next.Interfaces[0].Label != "after" {
		t.Fatal("planning mutated labels")
	}
	for _, change := range []struct {
		name string
		edit func(*config.Interface)
	}{
		{"kernel name", func(i *config.Interface) { i.Name = "qa-other-port" }},
		{"MTU", func(i *config.Interface) { i.MTU = 1400 }},
		{"disable", func(i *config.Interface) { i.Enabled = false }},
		{"link mode", func(i *config.Interface) { i.LinkMode = "100-full" }},
		{"MAC", func(i *config.Interface) { i.MAC = "02:00:00:00:00:01" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			mixed := next
			mixed.Interfaces = append([]config.Interface(nil), next.Interfaces...)
			change.edit(&mixed.Interfaces[0])
			actions, err := s.Plan(old, &mixed)
			if err != nil || len(actions) != 1 {
				t.Fatalf("runtime change lost from plan: %v %v", actions, err)
			}
		})
	}
}

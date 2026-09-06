package netiface

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestReport1953BondCreationAndModeDrift(t *testing.T) {
	newFakeNet(t)
	r := &linkRunner{}
	cfg := config.Default()
	iface := config.Interface{ID: "bond", Name: "bond1", Type: "bond", Enabled: true}
	s := &Interfaces{Runner: r, owned: map[string]bool{"bond1": true}}
	if err := s.ensure(context.Background(), cfg, iface); err != nil {
		t.Fatal(err)
	}
	if !r.has("type bond mode balance-rr") {
		t.Fatalf("mode depends on kernel defaults: %v", r.commands)
	}
	mode := filepath.Join(sysClassNet, "bond1", "bonding", "mode")
	if err := os.MkdirAll(filepath.Dir(mode), 0755); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"802.3ad 4", "balance-rr 0"} {
		if err := os.WriteFile(mode, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
		mismatch := describeMismatch(cfg, iface)
		if (mismatch != "") != strings.HasPrefix(value, "802.3ad") {
			t.Fatalf("mode %s mismatch=%q", value, mismatch)
		}
	}
}

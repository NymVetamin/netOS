package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestZoneConflictCorrectionKeepsPoliciesSeparate(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "a", Name: "eth1", Type: "physical", Enabled: true}, {ID: "b", Name: "eth2", Type: "physical", Enabled: true}}
	cfg.Firewall.Zones = append(cfg.Firewall.Zones, config.Zone{Name: "LAN", Policy: "reject"})
	cfg.Networks = []config.Network{{ID: "a", Name: "Office", Interface: "a", Zone: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}, {ID: "b", Name: "Guests", Interface: "b", Zone: "LAN", Enabled: true, RouterAddress: "192.0.3.1/24"}}
	cfg.Normalize()
	if !cfg.Validate().HasErrors() {
		t.Fatal("colliding zones accepted")
	}
	cfg.Firewall.Zones[len(cfg.Firewall.Zones)-1].Name = "Guests"
	cfg.Networks[1].Zone = "Guests"
	for range 2 {
		cfg.Normalize()
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatal(result.Problems)
		}
		rules, err := Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range []string{":LAN-IN - [0:0]", ":GUESTS-IN - [0:0]"} {
			if strings.Count(rules.IPv4, declaration) != 1 {
				t.Fatalf("missing or duplicate %s", declaration)
			}
		}
		for _, rule := range []string{"-A INPUT -i eth1 -j LAN-IN", "-A INPUT -i eth2 -j GUESTS-IN", "-A LAN-IN -m comment --comment \"политика зоны\" -j ACCEPT", "-A GUESTS-IN -m comment --comment \"политика зоны\" -j REJECT"} {
			if !strings.Contains(rules.IPv4, rule) {
				t.Fatalf("missing policy/dispatch %q", rule)
			}
		}
	}
}

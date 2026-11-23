package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestInterfacePrefixSelectorsAndDestinationExpansion(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "eth1"}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan", Zone: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}
	cfg.Firewall.Rules = []config.FirewallRule{{ID: "prefix", Name: "prefix fixture", Enabled: true, Zone: "global", Flow: "forward", Interface: "eth+", OutInterface: "eth+", Action: "accept"}}
	for _, destination := range []string{"", "lan", ""} {
		cfg.Firewall.Rules[0].DstZone = destination
		rules, err := Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, line := range strings.Split(rules.IPv4, "\n") {
			if !strings.Contains(line, `--comment "prefix fixture"`) {
				continue
			}
			found = true
			if !strings.Contains(line, " -i eth+") || !strings.Contains(line, " -o eth+") {
				t.Fatalf("prefix lost: %s", line)
			}
		}
		if found != (destination == "") {
			t.Fatalf("destination %q: prefix rule emitted=%v", destination, found)
		}
	}
}

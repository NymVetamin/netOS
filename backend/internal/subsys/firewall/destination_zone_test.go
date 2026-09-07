package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestGlobalForwardRuleRestrictsDestinationZone(t *testing.T) {
	for _, source := range []string{"global", "lan"} {
		for _, destination := range []string{"wan", "vpn", ""} {
			t.Run(source+"/"+destination, func(t *testing.T) {
				cfg := config.Default()
				cfg.Interfaces = []config.Interface{{ID: "l", Name: "lan0"}, {ID: "w1", Name: "wan0"}, {ID: "w2", Name: "wan1"}}
				cfg.Networks = []config.Network{{ID: "lan", Interface: "l", Zone: "lan", Enabled: true}}
				cfg.WANs = []config.WAN{{ID: "w1", Interface: "w1", Enabled: true}, {ID: "w2", Interface: "w2", Enabled: true}}
				cfg.Channels = nil
				cfg.VPNServers = nil
				cfg.Firewall.Rules = []config.FirewallRule{{ID: "test", Name: "destination-bound", Enabled: true, Zone: source, Flow: "forward", DstZone: destination, Action: "drop", Protocol: "tcp", DstPort: "8001"}}
				rs, err := Build(cfg)
				if err != nil {
					t.Fatal(err)
				}
				var lines []string
				for _, line := range strings.Split(rs.IPv4, "\n") {
					if strings.Contains(line, `--comment "destination-bound"`) {
						lines = append(lines, line)
					}
				}
				switch destination {
				case "wan":
					if len(lines) != 2 {
						t.Fatalf("want one rule per WAN interface, got %v", lines)
					}
					for i, iface := range []string{"wan0", "wan1"} {
						if !strings.Contains(lines[i], " -o "+iface+" ") {
							t.Errorf("missing destination interface %s: %s", iface, lines[i])
						}
					}
				case "vpn":
					if len(lines) != 0 {
						t.Fatalf("empty destination zone must not match other traffic: %v", lines)
					}
				case "":
					if len(lines) != 1 || strings.Contains(lines[0], " -o ") {
						t.Fatalf("unrestricted destination changed: %v", lines)
					}
				}
			})
		}
	}
}

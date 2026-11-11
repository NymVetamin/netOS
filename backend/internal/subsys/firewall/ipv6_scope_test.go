package firewall

import (
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIPv6SystemRuleScope(t *testing.T) {
	for _, id := range []string{config.RuleSSH, config.RulePanel} {
		for _, tc := range []struct {
			name, zone, iface, flow, want string
		}{
			{"global", "global", "", "in", "-A INPUT -p tcp"},
			{"lan", "lan", "", "in", "-A INPUT -i br-lan -p tcp"},
			{"wan", "wan", "", "in", "-A INPUT -i eth0 -p tcp"},
			{"empty zone", "vpn", "", "in", ""},
			{"intersection", "lan", "br-lan", "in", "-A INPUT -i br-lan -p tcp"},
			{"outside zone", "lan", "eth0", "in", ""},
			{"global interface", "global", "eth0", "in", "-A INPUT -i eth0 -p tcp"},
			{"outgoing", "global", "", "out", ""},
			{"forward", "lan", "", "forward", ""},
		} {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				cfg := ipv6PassthroughConfig()
				for i := range cfg.Interfaces {
					cfg.Interfaces[i].Type, cfg.Interfaces[i].Enabled = "physical", true
				}
				var name string
				for i := range cfg.Firewall.Rules {
					r := &cfg.Firewall.Rules[i]
					if r.ID == id {
						r.Zone, r.Interface, r.Flow = tc.zone, tc.iface, tc.flow
						name = r.Name
					}
				}
				cfg.Normalize()
				if result := cfg.Validate(); result.HasErrors() {
					t.Fatalf("invalid fixture: %v", result.Problems)
				}
				var matches []string
				rules := buildIPv6(cfg)
				for _, line := range strings.Split(rules, "\n") {
					if strings.Contains(line, fmt.Sprintf("--comment %q", name)) {
						matches = append(matches, line)
					}
				}
				if tc.want == "" {
					if len(matches) != 0 {
						t.Fatalf("unexpected permission: %v", matches)
					}
				} else if len(matches) != 1 || !strings.HasPrefix(matches[0], tc.want) || strings.Count(matches[0], " -i ") > 1 {
					t.Fatalf("want %q, got %v", tc.want, matches)
				}
				if again := buildIPv6(cfg); again != rules {
					t.Fatal("repeat changed rules")
				}
			})
		}
	}
}

func TestIPv6SystemRuleZoneRefresh(t *testing.T) {
	cfg := ipv6PassthroughConfig()
	for i := range cfg.Firewall.Rules {
		if cfg.Firewall.Rules[i].ID != config.RuleSSH {
			continue
		}
		r := &cfg.Firewall.Rules[i]
		for _, zone := range []string{"lan", "wan", "lan"} {
			r.Zone = zone
			rules := buildIPv6(cfg)
			iface := "br-lan"
			if zone == "wan" {
				iface = "eth0"
			}
			want := "-A INPUT -i " + iface + " -p tcp -m multiport --dports 22 "
			if !strings.Contains(rules, want) {
				t.Fatalf("zone %s not reflected:\n%s", zone, rules)
			}
		}
	}
}

// Includes zone preparation and both address families, as in Plan/Apply.
func BenchmarkBuildIPv6SystemRuleScope(b *testing.B) {
	for _, size := range []int{8, 128} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			cfg := ipv6PassthroughConfig()
			for i := range cfg.Firewall.Rules {
				if cfg.Firewall.Rules[i].ID == config.RuleSSH || cfg.Firewall.Rules[i].ID == config.RulePanel {
					cfg.Firewall.Rules[i].Zone = "lan"
				}
			}
			for i := 1; i < size; i++ {
				id := fmt.Sprintf("lan%d", i)
				cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: id, Name: id})
				cfg.Networks = append(cfg.Networks, config.Network{ID: id, Interface: id, Zone: "lan", Enabled: true, RouterAddress: fmt.Sprintf("10.0.%d.1/24", i)})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Build(cfg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

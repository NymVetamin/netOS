package config

import (
	"fmt"
	"testing"
)

func TestFirewallZoneChainIdentity(t *testing.T) {
	for _, names := range [][2]string{{"lan", "LAN"}, {"Guest", "gUeSt"}, {"Guest", "Guest"}, {"gUeSt", "Guest"}, {"LAN", "lan"}} {
		for _, enabled := range []bool{true, false} {
			cfg := Default()
			cfg.Firewall.Rules = []FirewallRule{{ID: "access", Enabled: true, Zone: "global", Flow: "in", Protocol: "tcp", DstPort: "22", Action: "accept"}}
			cfg.Firewall.Enabled = enabled
			cfg.Firewall.Zones = []Zone{{Name: names[0], Policy: "accept"}, {Name: names[1], Policy: "reject"}}
			for range 2 {
				cfg.Normalize()
				if !problem(t, cfg, "firewall.zones[1].name", "") {
					t.Errorf("%v enabled=%t: ambiguous chains accepted", names, enabled)
				}
			}
			cfg.Firewall.Zones[1].Name = "Separate"
			if result := cfg.Validate(); result.HasErrors() {
				t.Fatalf("distinct mixed-case zones rejected: %+v", result.Problems)
			}
		}
	}
}

func BenchmarkValidateZoneIdentity(b *testing.B) {
	for _, n := range []int{16, 2048} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := Default()
			cfg.Firewall.Rules = []FirewallRule{{ID: "access", Enabled: true, Zone: "global", Flow: "in", Protocol: "tcp", DstPort: "22", Action: "accept"}}
			cfg.Firewall.Zones = make([]Zone, n)
			for i := range cfg.Firewall.Zones {
				cfg.Firewall.Zones[i] = Zone{Name: fmt.Sprintf("zone%d", i), Policy: "drop"}
			}
			b.ReportAllocs()
			for b.Loop() {
				if result := cfg.Validate(); result.HasErrors() {
					b.Fatal(result.Problems)
				}
			}
		})
	}
}

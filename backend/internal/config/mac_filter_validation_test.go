package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestFilterMACLength(t *testing.T) {
	for _, tc := range []struct {
		mac string
		bad bool
	}{
		{"", false}, {"02:00:00:AB:cd:01", false},
		{"02-00-00-ab-cd-01", false}, {"0200.00ab.cd01", false},
		{"02:00:00:00:00:00:00:01", true},
		{strings.Repeat("00:", 19) + "01", true},
		{"02:00:00:00:01", true}, {"invalid", true},
	} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enabled=%t", tc.mac, enabled), func(t *testing.T) {
				c := Default()
				i := len(c.Firewall.Rules)
				c.Firewall.Rules = append(c.Firewall.Rules, FirewallRule{ID: "mac-filter", Enabled: enabled, Zone: "global", Flow: "in", Action: "drop", SrcMAC: tc.mac})
				c.Policies = []Policy{{ID: "mac-policy", Enabled: enabled, Channel: InternetBlockChannel, SrcMAC: tc.mac}}
				paths := []string{fmt.Sprintf("firewall.rules[%d].src_mac", i), "policies[0].src_mac"}
				for repeat := 0; repeat < 2; repeat++ {
					c.Normalize()
					r := c.Validate()
					for _, path := range paths {
						if got := hasErrorAt(r, path); got != tc.bad {
							t.Errorf("%s error=%t want=%t: %+v", path, got, tc.bad, r.Problems)
						}
					}
					if !tc.bad && r.HasErrors() {
						t.Fatalf("valid filter rejected: %+v", r.Problems)
					}
				}
				c.Firewall.Rules[i].SrcMAC = "02:00:00:00:00:01"
				c.Policies[0].SrcMAC = "02:00:00:00:00:01"
				if r := c.Validate(); r.HasErrors() {
					t.Fatalf("corrected filter rejected: %+v", r.Problems)
				}
			})
		}
	}
}

func BenchmarkValidateMACFilters(b *testing.B) {
	for _, n := range []int{16, 2048} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := Default()
			for i := 0; i < n; i++ {
				c.Firewall.Rules = append(c.Firewall.Rules, FirewallRule{ID: fmt.Sprintf("r%d", i), Enabled: true, Zone: "global", Flow: "in", Action: "drop", SrcMAC: "02:00:00:00:00:01"})
			}
			b.ReportAllocs()
			for b.Loop() {
				if r := c.Validate(); r.HasErrors() {
					b.Fatal(r.Problems)
				}
			}
		})
	}
}

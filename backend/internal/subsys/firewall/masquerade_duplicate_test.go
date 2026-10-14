package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestWANMasqueradeDoesNotDuplicateExplicitCatchAll(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rule     config.NATRule
		wantAuto bool
	}{
		{"bootstrap", config.NATRule{Enabled: true, System: true, Direction: "source", Interface: "eth0"}, false},
		{"user", config.NATRule{Enabled: true, Interface: "eth0"}, false},
		{"disabled", config.NATRule{Interface: "eth0"}, false},
		{"subnet", config.NATRule{Enabled: true, Interface: "eth0", Source: "192.0.2.0/24"}, true},
		{"snat", config.NATRule{Enabled: true, Interface: "eth0", ToSource: "198.51.100.2"}, true},
		{"other interface", config.NATRule{Enabled: true, Interface: "eth1"}, true},
		{"destination", config.NATRule{Enabled: true, Interface: "eth0", Direction: "destination"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Interfaces = []config.Interface{{ID: "wan", Name: "eth0", Enabled: true}}
			cfg.WANs = []config.WAN{{ID: "wan", Name: "uplink", Interface: "wan", Enabled: true}}
			cfg.Firewall.NAT = []config.NATRule{tc.rule}
			for i := 0; i < 2; i++ {
				rules, err := Build(cfg)
				if err != nil {
					t.Fatal(err)
				}
				auto := strings.Contains(rules.IPv4, "NAT аплинка")
				if auto != tc.wantAuto {
					t.Fatalf("automatic masquerade = %v, want %v", auto, tc.wantAuto)
				}
				expected := 0
				if tc.rule.Enabled {
					expected = 1
				}
				if !tc.wantAuto && strings.Count(rules.IPv4, "-A POSTROUTING -o eth0 ") != expected {
					t.Fatal("duplicate catch-all")
				}
				if tc.rule.ToSource != "" && strings.Index(rules.IPv4, "-j SNAT") > strings.Index(rules.IPv4, "NAT аплинка") {
					t.Fatal("SNAT lost priority")
				}
			}
		})
	}
}

func TestExplicitMasqueradeToggleKeepsOtherWAN(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "wan", Name: "eth0", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "wan", Name: "uplink", Interface: "wan", Enabled: true},
		{ID: "backup", Name: "backup", Proto: "pppoe", Enabled: true}}
	cfg.Firewall.NAT = []config.NATRule{{System: true, Direction: "source", Interface: "eth0"}}
	for _, enabled := range []bool{true, false, true, false} {
		cfg.Firewall.NAT[0].Enabled = enabled
		rules, err := Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		count := strings.Count(rules.IPv4, "-A POSTROUTING -o eth0 ")
		expected := 0
		if enabled {
			expected = 1
		}
		if count != expected {
			t.Fatalf("enabled=%v: got %d rules, want %d", enabled, count, expected)
		}
		if !strings.Contains(rules.IPv4, "-A POSTROUTING -o ppp-backup ") {
			t.Fatal("unmanaged WAN lost automatic NAT")
		}
	}
}

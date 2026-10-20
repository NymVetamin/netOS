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

func TestChannelMasqueradeControl(t *testing.T) {
	for typ, iface := range map[string]string{
		"wireguard": "wg-ch1", "openconnect": "tun-ch1", "xray": "tun-ch1",
		"l2tp": "ppp-ch1", "ikev2": "xfrm-ch1",
	} {
		t.Run(typ, func(t *testing.T) {
			cfg := config.Default()
			cfg.Channels = []config.Channel{
				{ID: "test", Name: "test", Type: typ, Index: 1, Enabled: true},
				{ID: "other", Name: "other", Type: "wireguard", Index: 2, Enabled: true},
			}
			for _, tc := range []struct {
				name string
				rule *config.NATRule
				auto bool
			}{
				{"legacy default", nil, true},
				{"off", &config.NATRule{Interface: iface, System: true}, false},
				{"on", &config.NATRule{Interface: iface, System: true, Enabled: true}, false},
				{"off again", &config.NATRule{Interface: iface, System: true}, false},
				{"manual on", &config.NATRule{Interface: iface, Enabled: true}, false},
				{"manual off", &config.NATRule{Interface: iface}, false},
				{"subnet", &config.NATRule{Interface: iface, Source: "192.0.2.0/24", Enabled: true}, true},
				{"SNAT", &config.NATRule{Interface: iface, ToSource: "198.51.100.2", Enabled: true}, true},
				{"DNAT", &config.NATRule{Interface: iface, Direction: "destination", Enabled: true, Protocol: "tcp", ExtPort: "80", DestIP: "192.0.2.2"}, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cfg.Firewall.NAT = nil
					if tc.rule != nil {
						cfg.Firewall.NAT = []config.NATRule{*tc.rule}
					}
					var b builder
					b.nat(cfg, buildZoneMap(cfg))
					text := b.String()
					auto := strings.Contains(text, `--comment "NAT канала «test»"`)
					if auto != tc.auto {
						t.Fatalf("automatic NAT=%v, want %v:\n%s", auto, tc.auto, text)
					}
					if tc.rule != nil && !tc.auto {
						want := 0
						if tc.rule.Enabled {
							want = 1
						}
						if got := strings.Count(text, "-A POSTROUTING -o "+iface+" "); got != want {
							t.Fatalf("got %d NAT rules, want %d", got, want)
						}
					}
					if !strings.Contains(text, "-A POSTROUTING -o wg-ch2 ") {
						t.Fatal("other channel lost NAT")
					}
					if tc.name == "SNAT" && strings.Index(text, "-j SNAT") > strings.Index(text, `"NAT канала «test»"`) {
						t.Fatal("explicit SNAT lost precedence")
					}
				})
			}
		})
	}
}

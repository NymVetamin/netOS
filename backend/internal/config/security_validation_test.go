package config

import (
	"strings"
	"testing"
)

func hasErrorAt(result *ValidationResult, prefix string) bool {
	for _, problem := range result.Problems {
		if problem.Severity == "error" && strings.HasPrefix(problem.Path, prefix) {
			return true
		}
	}
	return false
}

func TestValidationRejectsPathAndConfigInjectionInWAN(t *testing.T) {
	for _, tc := range []struct {
		path   string
		mutate func(*WAN)
	}{
		{"wans[0].id", func(w *WAN) { w.ID = "../../owned" }},
		{"wans[0]", func(w *WAN) { w.Username = "user\nname = attacker" }},
		{"wans[0]", func(w *WAN) { w.Password = "secret\x00tail" }},
		{"wans[0].server", func(w *WAN) { w.Proto = "l2tp"; w.Server = "vpn.example.com\nredial = yes" }},
	} {
		cfg := Default()
		cfg.Interfaces = []Interface{{ID: "eth0", Name: "eth0", Type: "physical", Enabled: true}}
		cfg.WANs = []WAN{{ID: "wan1", Index: 1, Name: "WAN", Interface: "eth0", Enabled: true, Proto: "pppoe", Username: "user", Password: "password", Metric: 100}}
		tc.mutate(&cfg.WANs[0])
		if result := cfg.Validate(); !hasErrorAt(result, tc.path) {
			t.Fatalf("unsafe WAN accepted: %#v", cfg.WANs[0])
		}
	}
}

func TestValidationRejectsUnsafeHostSettings(t *testing.T) {
	cfg := Default()
	cfg.System.Hostname = "router\nattacker"
	cfg.System.Timezone = "../../etc/passwd"
	result := cfg.Validate()
	if !hasErrorAt(result, "system.hostname") || !hasErrorAt(result, "system.timezone") {
		t.Fatalf("unsafe host settings accepted: %#v", result.Problems)
	}
}

func TestValidationRejectsInjectedIdentifiersAcrossObjectFamilies(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = append(cfg.Interfaces, Interface{ID: "if\nmalicious", Name: "eth0", Type: "physical"})
	cfg.Networks = append(cfg.Networks, Network{ID: "../network", Name: "bad", Interface: cfg.Interfaces[0].ID})
	cfg.Firewall.Zones = []Zone{{Name: "lan\n-A INPUT -j ACCEPT", Policy: "drop"}}
	cfg.DNS.Upstreams = []Upstream{{ID: "dns/../../x"}}
	cfg.Channels = []Channel{{ID: "direct\nmalicious"}}
	cfg.VPNServers = []VPNServer{{ID: "../server", Peers: []VPNPeer{{ID: "peer\nmalicious"}}}}
	cfg.WiFi = []WiFiRadio{{ID: "../radio", SSIDs: []WiFiSSID{{ID: "ssid/evil"}}}}

	result := cfg.Validate()
	for _, want := range []string{
		"interfaces[0].id", "networks[0].id", "firewall.zones[0].name",
		"dns.upstreams[0].id", "channels[0].id", "vpn_servers[0].id",
		"vpn_servers[0].peers[0].id", "wifi[0].id", "wifi[0].ssids[0].id",
	} {
		if !hasErrorAt(result, want) {
			t.Errorf("нет ошибки для %s", want)
		}
	}
}

package config

import (
	"strings"
	"testing"
)

func TestHumanNameValidationMatchesOneLineBrowserInputs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		invalid bool
	}{
		{"unicode and quotes", `Сеть 日本語 "quoted" 'single'`, false},
		{"256 bytes", strings.Repeat("x", 256), false},
		{"leading spaces", " name", true},
		{"trailing spaces", "name ", true},
		{"newline", "line1\nline2", true},
		{"control", "name\x00tail", true},
		{"257 bytes", strings.Repeat("x", 257), true},
		{"4096 bytes", strings.Repeat("x", 4096), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Networks = append(cfg.Networks, Network{ID: "qa", Name: tc.value})
			got := hasErrorAt(cfg.Validate(), "networks[0].name")
			if got != tc.invalid {
				t.Fatalf("name invalid=%v, want %v", got, tc.invalid)
			}
		})
	}
}

func TestHumanTextValidationCoversConfigurationFamilies(t *testing.T) {
	cfg := Default()
	bad := "line1\nline2"
	cfg.Networks = []Network{{ID: "qa", Name: bad}}
	cfg.WANs = []WAN{{ID: "qa", Name: bad, Service: bad, AC: bad}}
	cfg.Routing.Static = []StaticRoute{{ID: "qa", Name: bad, Comment: bad}}
	cfg.Routing.Tables = []RouteTable{{ID: "qa", Name: "qa", Number: 200, Comment: bad}}
	cfg.Routing.Rules = []RouteRule{{ID: "qa", Name: bad, Comment: bad}}
	cfg.Firewall.Zones = []Zone{{Name: "qa", Title: bad, Description: bad}}
	cfg.Firewall.Rules = []FirewallRule{{ID: "qa", Name: bad, Comment: bad}}
	cfg.Firewall.NAT = []NATRule{{ID: "qa", Name: bad, Comment: bad}}
	cfg.DHCP.Reservations = []Reservation{{ID: "qa", Comment: bad}}
	cfg.DNS.Upstreams = []Upstream{{ID: "qa", Comment: bad}}
	cfg.DNS.Blocklists = []Blocklist{{ID: "qa", Name: bad}}
	cfg.Clients = []Client{{ID: "qa", Name: bad, Comment: bad}}
	cfg.Channels = []Channel{{ID: "qa", Name: bad}}
	cfg.Policies = []Policy{{ID: "qa", Name: bad, Comment: bad}}
	cfg.VPNServers = []VPNServer{{ID: "qa", Name: bad, Peers: []VPNPeer{{ID: "peer", Name: bad, Comment: bad}}}}
	cfg.WiFi = []WiFiRadio{{ID: "qa", SSIDs: []WiFiSSID{{ID: "ssid", SSID: bad}}}}

	result := cfg.Validate()
	for _, path := range []string{
		"networks[0].name", "wans[0].name", "wans[0].service", "wans[0].ac",
		"routing.static[0].name", "routing.static[0].comment", "routing.tables[0].comment",
		"routing.rules[0].name", "routing.rules[0].comment", "firewall.zones[0].title",
		"firewall.zones[0].description", "firewall.rules[0].name", "firewall.rules[0].comment",
		"firewall.nat[0].name", "firewall.nat[0].comment", "dhcp.reservations[0].comment",
		"dns.upstreams[0].comment", "dns.blocklists[0].name", "clients[0].name",
		"clients[0].comment", "channels[0].name", "policies[0].name", "policies[0].comment",
		"vpn_servers[0].name", "vpn_servers[0].peers[0].name",
		"vpn_servers[0].peers[0].comment", "wifi[0].ssids[0].ssid",
	} {
		if !hasErrorAt(result, path) {
			t.Errorf("unsafe human text accepted at %s", path)
		}
	}
}

func TestHumanCommentLengthIsExplicit(t *testing.T) {
	cfg := Default()
	cfg.Firewall.Rules = []FirewallRule{{ID: "qa", Comment: strings.Repeat("x", maxHumanCommentBytes)}}
	if result := cfg.Validate(); hasErrorAt(result, "firewall.rules[0].comment") {
		t.Fatalf("comment at documented limit rejected: %#v", result.Problems)
	}
	cfg.Firewall.Rules[0].Comment += "x"
	if result := cfg.Validate(); !hasErrorAt(result, "firewall.rules[0].comment") {
		t.Fatal("overlong comment accepted")
	}
}

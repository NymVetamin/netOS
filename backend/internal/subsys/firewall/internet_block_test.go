package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestInternetBlockRebuildAndAddressFamilies(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	cfg.Clients = []config.Client{{MAC: "02:00:00:00:00:01"}}
	cfg.VPNServers = []config.VPNServer{{Type: "wireguard", Index: 1, Enabled: true,
		Peers: []config.VPNPeer{{Enabled: true, Address: "192.0.2.2"}}}}
	for _, firewall := range []bool{false, true} {
		cfg.Firewall.Enabled = firewall
		for _, state := range []struct{ lan, vpn bool }{{true, true}, {false, true}, {false, false}, {true, false}, {true, true}} {
			cfg.Clients[0].Channel = "direct"
			cfg.VPNServers[0].Peers[0].Channel = "direct"
			if state.lan {
				cfg.Clients[0].Channel = config.InternetBlockChannel
			}
			if state.vpn {
				cfg.VPNServers[0].Peers[0].Channel = config.InternetBlockChannel
			}
			rules, err := Build(cfg)
			if err != nil {
				t.Fatal(err)
			}
			for family, text := range []string{rules.IPv4, rules.IPv6} {
				want := state.lan || (family == 0 && state.vpn)
				if strings.Contains(text, ":NETOS-INTERNET-BLOCK") != want ||
					strings.Contains(text, "-j MARK --set-mark "+internetBlockMark) != want {
					t.Fatalf("firewall=%t state=%+v family=%d: stale or missing block", firewall, state, family)
				}
			}
		}
	}
}

func TestInternetBlockIPv6InternalInterfaceNames(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	cfg.Clients = []config.Client{{MAC: "02:00:00:00:00:01", Channel: config.InternetBlockChannel}}
	cfg.Interfaces = []config.Interface{
		{ID: "first", Name: "lan0"}, {ID: "first", Name: "wrong0"},
		{ID: "empty"}, {ID: "empty", Name: "wrong1"},
		{ID: "unused", Name: "wrong2"}, {ID: "same", Name: "lan0"},
	}
	cfg.Networks = []config.Network{
		{Interface: "first", Enabled: true}, {Interface: "empty", Enabled: true},
		{Interface: "unknown", Enabled: true}, {Interface: "unused"},
		{Interface: "same", Enabled: true},
	}
	for _, name := range []string{"lan0", "renamed0", ""} {
		cfg.Interfaces[0].Name = name
		rules := buildIPv6(cfg)
		if strings.Contains(rules, "wrong") || strings.Contains(rules, "-o  ") {
			t.Fatal("duplicate, missing or disabled interface changed selection")
		}
		want := "-A NETOS-INTERNET-BLOCK -o lan0 -j RETURN"
		if strings.Count(rules, want) != 1 {
			t.Fatal("shared interface not deduplicated")
		}
		if strings.Contains(rules, "-o renamed0 -j RETURN") != (name == "renamed0") {
			t.Fatal("interface rename was not refreshed")
		}
	}
}

func TestInternetBlockPreservesInternalAndRouterAccess(t *testing.T) {
	cfg := config.Default()
	cfg.Clients = []config.Client{{ID: "phone", MAC: "02:00:00:00:00:02", Channel: config.InternetBlockChannel}}
	cfg.Networks = append(cfg.Networks, config.Network{ID: "other", Enabled: true, RouterAddress: "10.22.0.1/24"})
	for _, enabled := range []bool{true, false} {
		cfg.Firewall.Enabled = enabled
		rs, err := Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		rules := rs.IPv4
		for _, want := range []string{"-A FORWARD -m mark --mark " + internetBlockMark, "-A NETOS-INTERNET-BLOCK -d 10.22.0.0/24 -j RETURN", "-A NETOS-INTERNET-BLOCK -j DROP", "-A PREROUTING -m mac --mac-source 02:00:00:00:00:02 -j MARK --set-mark " + internetBlockMark} {
			if !strings.Contains(rules, want) {
				t.Fatalf("missing %s", want)
			}
		}
		if strings.Contains(rules, "-A INPUT -m mac --mac-source") {
			t.Fatal("internet block denied router services")
		}
		if enabled && strings.Index(rules, "-A FORWARD -m mark") > strings.Index(rules, "--ctstate ESTABLISHED,RELATED") {
			t.Fatal("block after established")
		}
	}
	cfg.Clients[0].Channel = "direct"
	rs, _ := Build(cfg)
	if strings.Contains(rs.IPv4, "NETOS-INTERNET-BLOCK") {
		t.Fatal("unblock left rules")
	}
}

func TestInternetBlockVPNAndIPv6Selectors(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	cfg.Clients = []config.Client{{MAC: "02:00:00:00:00:02", Channel: config.InternetBlockChannel}}
	for i, kind := range []string{"wireguard", "ocserv", "ikev2", "l2tp", "xray"} {
		cfg.VPNServers = append(cfg.VPNServers, config.VPNServer{ID: kind, Index: i + 1, Type: kind, Enabled: true, Subnet: "10.9.0.1/24", Peers: []config.VPNPeer{{ID: "p", Enabled: true, Address: "10.9.0.2", Channel: config.InternetBlockChannel}}})
	}
	matches := internetBlockMatches(cfg, false)
	if len(matches) != 5 {
		t.Fatalf("matches: %v", matches)
	}
	if !strings.Contains(strings.Join(matches, "\n"), "--pol ipsec") {
		t.Fatal("IKE peer loses IPsec selector")
	}
	rs, _ := Build(cfg)
	if !strings.Contains(rs.IPv6, "-A FORWARD -m mark --mark "+internetBlockMark) {
		t.Fatal("IPv6 bypass")
	}
}

func TestInternetBlockUsesOneFilterMatch(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	cfg.Clients = []config.Client{{MAC: "02:00:00:00:00:02", Channel: config.InternetBlockChannel}, {MAC: "02:00:00:00:00:03", Channel: config.InternetBlockChannel}}
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "exit", Index: 1, Type: "wireguard", Enabled: true})
	cfg.Networks = []config.Network{{Enabled: true, RouterAddress: "192.0.2.1/24", DefaultChannel: "exit"}}
	cfg.MultiWAN.Enabled = true
	cfg.MultiWAN.Mode = "balance"
	cfg.MultiWAN.StickyConnections = true
	cfg.WANs = []config.WAN{{ID: "w1", Index: 1, Enabled: true, Weight: 1}, {ID: "w2", Index: 2, Enabled: true, Weight: 1}}
	rs, _ := Build(cfg)
	for _, rules := range []string{rs.IPv4, rs.IPv6} {
		filter := rules[strings.Index(rules, "*filter"):]
		if strings.Contains(filter, "--mac-source") {
			t.Fatal("filter repeats client classification")
		}
		if strings.Count(filter, "-j NETOS-INTERNET-BLOCK") != 1 {
			t.Fatal("expected one filter jump")
		}
		for _, mac := range []string{"02:00:00:00:00:02", "02:00:00:00:00:03"} {
			if strings.Count(rules, "--mac-source "+mac) != 1 {
				t.Fatal("client not classified exactly once")
			}
		}
		if !strings.Contains(rules, "-A PREROUTING -m mark --mark "+internetBlockMark+" -j CONNMARK --set-mark 0") {
			t.Fatal("old exit mark survives")
		}
		if strings.Contains(rules, "-j CONNMARK --set-mark "+internetBlockMark) || strings.Contains(rules, "-m mark --mark "+internetBlockMark+" -j CONNMARK --save-mark") {
			t.Fatal("block persisted in conntrack")
		}
	}
	end := strings.Index(rs.IPv4, "-A PREROUTING -m mark --mark "+internetBlockMark+" -j ACCEPT")
	restore := strings.Index(rs.IPv4, "-A PREROUTING -m conntrack --ctdir ORIGINAL -j CONNMARK --restore-mark")
	if end < 0 || restore < 0 || end > restore {
		t.Fatal("block mark overwritten by routing")
	}
	cfg.Clients = nil
	for _, mode := range []string{"off", "passthrough"} {
		cfg.IPv6.Mode = mode
		rules := buildIPv6(cfg)
		if !strings.HasPrefix(rules, "*mangle\n") || strings.Contains(rules, internetBlockMark) {
			t.Fatal("old IPv6 mark rules not cleared")
		}
	}
}

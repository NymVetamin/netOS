package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestInterfaceMappingsZoneDeduplicationAndExpectedChains(t *testing.T) {
	channelCases := map[string]string{
		"wireguard": "wg-ch7", "l2tp": "ppp-ch7", "ikev2": "xfrm-ch7", "xray": "tun-ch7", "openconnect": "tun-ch7", "direct": "",
	}
	for kind, want := range channelCases {
		if got := channelInterface(config.Channel{Type: kind, Index: 7}); got != want {
			t.Errorf("channel %s=%q want=%q", kind, got, want)
		}
	}
	serverCases := map[string]string{"wireguard": "wg-srv8", "ocserv": "vpns8", "ikev2": "xfrm-srv8", "xray": ""}
	for kind, want := range serverCases {
		if got := serverInterface(config.VPNServer{Type: kind, Index: 8}); got != want {
			t.Errorf("server %s=%q want=%q", kind, got, want)
		}
	}

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "lan0"}, {ID: "wan", Name: "wan0"}}
	cfg.Networks = []config.Network{
		{ID: "n1", Interface: "lan", Zone: "lan", Enabled: true},
		{ID: "n2", Interface: "lan", Zone: "lan", Enabled: true},
		{ID: "disabled", Interface: "lan", Zone: "guest", Enabled: false},
	}
	cfg.WANs = []config.WAN{{ID: "w1", Interface: "wan", Proto: "dhcp", Enabled: true}, {ID: "w2", Interface: "wan", Proto: "pppoe", Enabled: true}}
	cfg.Channels = []config.Channel{{ID: "ch", Type: "wireguard", Index: 7, Enabled: true}, {ID: "direct", Type: "direct", Enabled: true}}
	cfg.VPNServers = []config.VPNServer{{ID: "srv", Type: "ocserv", Index: 8, Enabled: true}}
	zones := buildZoneMap(cfg)
	if strings.Join(zones["lan"], ",") != "lan0" || strings.Join(zones["wan"], ",") != "ppp-w2,wan0" || strings.Join(zones["vpn"], ",") != "vpns8,wg-ch7" {
		t.Fatalf("zones=%+v", zones)
	}
	wantChains := len(cfg.Firewall.Zones) * 3
	if got := ExpectedChains(cfg); len(got) != wantChains {
		t.Fatalf("chains=%v", got)
	}
	cfg.Firewall.Enabled = false
	if got := ExpectedChains(cfg); got != nil {
		t.Fatalf("disabled chains=%v", got)
	}
}

func TestRuleSelectorsScheduleLoggingAndTargets(t *testing.T) {
	schedule := config.Schedule{Days: []string{"Mon", "Wed"}, TimeStart: "08:01", TimeStop: "18:02:03"}
	rule := config.FirewallRule{
		Name: "detailed", Flow: "out", Interface: "eth0", Protocol: "tcp", SrcIP: "192.0.2.0/24", DstIP: "198.51.100.1",
		SrcMAC: "02:00:00:00:00:01", SrcPort: "1000-1002", DstPort: "80,443", ConnState: "new,related", Schedule: &schedule,
	}
	got := selectors(rule)
	for _, part := range []string{" -o eth0", " -p tcp", " -s 192.0.2.0/24", " -d 198.51.100.1", "--mac-source", "--sports 1000:1002", "--dports 80,443", "--ctstate NEW,RELATED", "--timestart 08:01", "--timestop 18:02:03", "--weekdays Mon,Wed", `--comment "detailed"`} {
		if !strings.Contains(got, part) {
			t.Errorf("selector missing %q: %s", part, got)
		}
	}
	emptySchedule := scheduleMatch(config.Schedule{})
	if emptySchedule != " -m time" {
		t.Fatalf("empty schedule=%q", emptySchedule)
	}
	if strings.Contains(emptySchedule, "--kerneltz") {
		t.Fatalf("unstable kernel timezone emitted: %q", emptySchedule)
	}
	if target("accept") != "ACCEPT" || target("reject") != "REJECT --reject-with icmp-port-unreachable" || target("continue") != "RETURN" || target("invalid") != "DROP" {
		t.Fatal("target matrix")
	}
	if strings.Join(protocols("tcpudp"), ",") != "tcp,udp" || strings.Join(protocols("icmp"), ",") != "icmp" {
		t.Fatal("protocol matrix")
	}
	if addressOf("192.0.2.1/24") != "192.0.2.1" || addressOf("192.0.2.1") != "192.0.2.1" {
		t.Fatal("addressOf")
	}
	if truncate("abcd", 4) != "abcd" || truncate("abcde", 4) != "abcd" {
		t.Fatal("truncate")
	}

	var b builder
	rule.Action, rule.Log = "reject", true
	b.emitRule("OUTPUT", rule, " -m mark --mark 1")
	text := b.String()
	if !strings.Contains(text, "-j LOG") || !strings.Contains(text, "-j REJECT --reject-with icmp-port-unreachable") {
		t.Fatalf("emit=%s", text)
	}
}

func TestNATSourceDestinationDNSAndChannelFields(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "wan", Name: "eth0"}, {ID: "lan", Name: "lan0"}}
	cfg.Networks = []config.Network{{ID: "lan", Name: "LAN", Interface: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}
	cfg.DNS.Enabled, cfg.DNS.ForceLocal, cfg.DNS.Port = true, true, 5353
	cfg.Channels = []config.Channel{
		{ID: "wg", Name: "WG", Enabled: true, Type: "wireguard", Index: 1},
		{ID: "oc", Name: "OC", Enabled: true, Type: "openconnect", Index: 2},
		{ID: "xr", Name: "XR", Enabled: true, Type: "xray", Index: 3},
		{ID: "skip", Name: "L2", Enabled: true, Type: "l2tp", Index: 4},
	}
	cfg.Firewall.NAT = []config.NATRule{
		{ID: "skip-disabled", Enabled: false, Direction: "source", Interface: "eth0"},
		{ID: "skip-empty", Enabled: true, Direction: "source"},
		{ID: "masq", Name: "dynamic", Enabled: true, Direction: "source", Interface: "eth0", Source: "192.0.2.0/24"},
		{ID: "snat", Name: "fixed", Enabled: true, Direction: "source", Interface: "eth0", ToSource: "198.51.100.8"},
		{ID: "dnat", Name: "range", Enabled: true, Direction: "destination", Interface: "eth0", Protocol: "tcpudp", ExtPort: "8000-8010", DestIP: "192.0.2.9", DestPort: "9000-9010", AllowFrom: "203.0.113.0/24"},
		{ID: "dnat-same", Name: "same", Enabled: true, Direction: "destination", Protocol: "tcp", ExtPort: "443", DestIP: "192.0.2.10"},
		{ID: "dnat-empty", Name: "empty", Enabled: true, Direction: "destination", Protocol: "udp", ExtPort: "53"},
	}
	var b builder
	b.nat(cfg, buildZoneMap(cfg))
	text := b.String()
	for _, part := range []string{
		"-s 192.0.2.0/24 -p udp --dport 53 ! -d 192.0.2.1", "--to-destination 192.0.2.1:5353",
		"-o wg-ch1", "-o tun-ch2", "-o tun-ch3", "-j MASQUERADE", "-j SNAT --to-source 198.51.100.8",
		"-i eth0 -s 203.0.113.0/24 -p tcp --dport 8000:8010", "--to-destination 192.0.2.9:9000-9010",
		"-p udp --dport 8000:8010", "-p tcp --dport 443", "--to-destination 192.0.2.10",
	} {
		if !strings.Contains(text, part) {
			t.Errorf("NAT missing %q:\n%s", part, text)
		}
	}
	if strings.Contains(text, "ppp-ch4") || strings.Contains(text, "skip-disabled") || strings.Contains(text, "dnat-empty") {
		t.Fatalf("skipped NAT emitted:\n%s", text)
	}
}

func TestPortForwardIsolationAndVPNServerAcceptAllTypes(t *testing.T) {
	cfg := config.Default()
	cfg.Networks = []config.Network{
		{ID: "a", Name: "A", Enabled: true, Isolated: true, RouterAddress: "192.0.2.1/24"},
		{ID: "b", Name: "B", Enabled: true, RouterAddress: "198.51.100.1/24"},
		{ID: "off", Name: "Off", Enabled: false, RouterAddress: "203.0.113.1/24"},
	}
	cfg.Firewall.NAT = []config.NATRule{
		{Enabled: false, Direction: "destination", DestIP: "192.0.2.2", ExtPort: "1"},
		{Enabled: true, Direction: "source", DestIP: "192.0.2.2", ExtPort: "1"},
		{Enabled: true, Direction: "destination", Name: "mapped", Protocol: "tcpudp", ExtPort: "8000-8010", DestIP: "192.0.2.2", DestPort: "9000-9010"},
		{Enabled: true, Direction: "destination", Name: "same", Protocol: "tcp", ExtPort: "443", DestIP: "192.0.2.3"},
	}
	cfg.VPNServers = []config.VPNServer{
		{Name: "WG", Enabled: true, Type: "wireguard", Port: 51820},
		{Name: "XR", Enabled: true, Type: "xray", Port: 443},
		{Name: "OC", Enabled: true, Type: "ocserv", Port: 4443},
		{Name: "IKE", Enabled: true, Type: "ikev2"},
		{Name: "Off", Enabled: false, Type: "wireguard", Port: 1},
	}
	var b builder
	b.portForwardAccept(cfg, "FORWARD")
	b.isolation(cfg, "FORWARD")
	b.vpnServerAccept(cfg, "INPUT")
	text := b.String()
	for _, part := range []string{"--dport 9000:9010", "-p udp --dport 9000:9010", "--dport 443", "-s 192.0.2.0/24 -d 198.51.100.0/24", "--dport 51820", "-p tcp --dport 443", "-p tcp --dport 4443", "-p udp --dport 4443", "--dport 500", "--dport 4500", "-p esp"} {
		if !strings.Contains(text, part) {
			t.Errorf("missing %q:\n%s", part, text)
		}
	}
	if strings.Contains(text, "203.0.113.0/24") || strings.Contains(text, "--dport 1 ") {
		t.Fatalf("disabled emitted:\n%s", text)
	}
}

func TestPolicySelectorsAllSourcesAndSchedules(t *testing.T) {
	cfg := config.Default()
	cfg.Networks = []config.Network{{ID: "net", RouterAddress: "192.0.2.1/24"}}
	cfg.VPNServers = []config.VPNServer{
		{ID: "wg", Type: "wireguard", Index: 1, Subnet: "10.1.0.1/24", Peers: []config.VPNPeer{{ID: "p", Address: "10.1.0.2"}}},
		{ID: "ike", Type: "ikev2", Index: 2, Subnet: "10.2.0.1/24", Peers: []config.VPNPeer{{ID: "p", Address: "10.2.0.2"}}},
	}
	schedule := &config.Schedule{Days: []string{"Fri"}, TimeStart: "01:00", TimeStop: "02:00"}
	base := config.Policy{Network: "net", SrcIP: "203.0.113.0/24", SrcMAC: "AA:BB:CC:DD:EE:FF", Protocol: "udp", DstIP: "198.51.100.1", DstPort: "53,5353", Schedule: schedule}
	got := policySelectors(cfg, base)
	for _, part := range []string{"-s 192.0.2.0/24", "-s 203.0.113.0/24", "--mac-source aa:bb:cc:dd:ee:ff", "-p udp", "-d 198.51.100.1", "--dports 53,5353", "--weekdays Fri"} {
		if !strings.Contains(got, part) {
			t.Errorf("base selector missing %q: %s", part, got)
		}
	}
	if got := policySelectors(cfg, config.Policy{VPNServer: "wg"}); !strings.Contains(got, "-i wg-srv1") {
		t.Fatalf("WG server=%q", got)
	}
	if got := policySelectors(cfg, config.Policy{VPNServer: "wg", VPNPeer: "p"}); !strings.Contains(got, "-i wg-srv1 -s 10.1.0.2/32") {
		t.Fatalf("WG peer=%q", got)
	}
	if got := policySelectors(cfg, config.Policy{VPNServer: "ike"}); !strings.Contains(got, "-s 10.2.0.0/24 -m policy --dir in --pol ipsec") {
		t.Fatalf("IKE server=%q", got)
	}
	if got := policySelectors(cfg, config.Policy{VPNServer: "ike", VPNPeer: "p"}); strings.Contains(got, "10.2.0.0/24") || !strings.Contains(got, "-m policy --dir in --pol ipsec -s 10.2.0.2/32") {
		t.Fatalf("IKE peer=%q", got)
	}
}

func TestChannelPoliciesExplicitClientPeerServerAndNetworkMatrix(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = []config.Channel{
		{ID: "wg", Name: "WG", Index: 1, Enabled: true, Type: "wireguard"},
		{ID: "oc", Name: "OC", Index: 2, Enabled: true, Type: "openconnect"},
		{ID: "xr", Name: "XR", Index: 3, Enabled: true, Type: "xray"},
		{ID: "off", Name: "Off", Index: 4, Enabled: false, Type: "wireguard"},
		{ID: "unsupported", Name: "Bad", Index: 5, Enabled: true, Type: "l2tp"},
	}
	cfg.Policies = []config.Policy{
		{ID: "disabled", Enabled: false, Priority: 1, Channel: "wg"},
		{ID: "z-direct", Name: "direct", Enabled: true, Priority: 10, Channel: "direct", SrcIP: "192.0.2.10"},
		{ID: "b-wg", Name: "explicit wg", Enabled: true, Priority: 20, Channel: "wg", DstIP: "198.51.100.1"},
		{ID: "a-oc", Name: "explicit oc", Enabled: true, Priority: 20, Channel: "oc", DstIP: "198.51.100.2"},
		{ID: "off-channel", Name: "off", Enabled: true, Priority: 30, Channel: "off", DstIP: "198.51.100.3"},
		{ID: "unsupported-channel", Name: "unsupported", Enabled: true, Priority: 31, Channel: "unsupported", DstIP: "198.51.100.4"},
		{ID: "missing-channel", Name: "missing", Enabled: true, Priority: 32, Channel: "missing", DstIP: "198.51.100.5"},
		{ID: "xray-server-policy", Name: "xray internal", Enabled: true, Priority: 5, Channel: "wg", VPNServer: "xray-server"},
	}
	cfg.Clients = []config.Client{
		{ID: "client", Name: "Client", MAC: "AA:BB:CC:DD:EE:01", Channel: "xr"},
		{ID: "blocked", Name: "Blocked", MAC: "AA:BB:CC:DD:EE:02", Channel: "wg", Blocked: true},
		{ID: "direct", Name: "Direct", MAC: "AA:BB:CC:DD:EE:03", Channel: "direct"},
	}
	cfg.VPNServers = []config.VPNServer{
		{ID: "xray-server", Name: "Xray", Enabled: true, Type: "xray", Index: 8},
		{ID: "disabled-server", Name: "Off", Enabled: false, Type: "wireguard", Index: 9, DefaultChannel: "wg"},
		{ID: "unsupported-server", Name: "Bad", Enabled: true, Type: "xray", Index: 10, DefaultChannel: "wg"},
		{ID: "wg-server", Name: "WG server", Enabled: true, Type: "wireguard", Index: 11, DefaultChannel: "oc", Peers: []config.VPNPeer{
			{ID: "active", Name: "WG peer", Enabled: true, Address: "10.11.0.2", Channel: "wg"},
			{ID: "off", Name: "Off", Enabled: false, Address: "10.11.0.3", Channel: "wg"},
			{ID: "direct", Name: "Direct", Enabled: true, Address: "10.11.0.4", Channel: "direct"},
		}},
		{ID: "oc-server", Name: "OC server", Enabled: true, Type: "ocserv", Index: 12, DefaultChannel: "direct", Peers: []config.VPNPeer{{ID: "active", Name: "OC peer", Enabled: true, Address: "10.12.0.2", Channel: "oc"}}},
		{ID: "ike-server", Name: "IKE server", Enabled: true, Type: "ikev2", Index: 13, Subnet: "10.13.0.1/24", DefaultChannel: "xr", Peers: []config.VPNPeer{{ID: "active", Name: "IKE peer", Enabled: true, Address: "10.13.0.2", Channel: "wg"}}},
	}
	cfg.Networks = []config.Network{
		{ID: "network", Name: "Network", Enabled: true, RouterAddress: "172.16.1.1/24", DefaultChannel: "wg"},
		{ID: "direct-network", Name: "Direct", Enabled: true, RouterAddress: "172.16.2.1/24", DefaultChannel: "direct"},
		{ID: "off-network", Name: "Off", Enabled: false, RouterAddress: "172.16.3.1/24", DefaultChannel: "wg"},
	}
	var b builder
	b.channelPolicies(cfg)
	text := b.String()
	for _, part := range []string{
		":NETOS-POLICY", "-s 192.0.2.10 -m comment --comment \"direct\" -j RETURN",
		"-d 198.51.100.2", "-d 198.51.100.1", "--mac-source aa:bb:cc:dd:ee:01",
		"-i wg-srv11 -s 10.11.0.2/32", "-i vpns12 -s 10.12.0.2/32", "-i wg-srv11 -m comment",
		"-s 10.13.0.2/32 -m policy --dir in --pol ipsec", "-s 10.13.0.0/24 -m policy --dir in --pol ipsec",
		"-s 172.16.1.0/24", "CONNMARK --save-mark",
	} {
		if !strings.Contains(text, part) {
			t.Errorf("channel policy missing %q:\n%s", part, text)
		}
	}
	for _, absent := range []string{"xray internal", "198.51.100.3", "198.51.100.4", "198.51.100.5", "aa:bb:cc:dd:ee:02", "10.11.0.3", "172.16.3.0/24"} {
		if strings.Contains(text, absent) {
			t.Errorf("skipped policy %q emitted:\n%s", absent, text)
		}
	}
	if strings.Index(text, "explicit oc") > strings.Index(text, "explicit wg") {
		t.Fatalf("same-priority ID sorting wrong:\n%s", text)
	}

	var empty builder
	empty.channelPolicies(config.Default())
	if empty.String() != "" {
		t.Fatalf("empty policies emitted %q", empty.String())
	}
}

func TestWANInterfacePPPAndStatic(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "if", Name: "eth9"}}
	if got := wanInterface(cfg, config.WAN{ID: "ppp", Proto: "pppoe", Interface: "if"}); got != "ppp-ppp" {
		t.Fatalf("pppoe=%q", got)
	}
	if got := wanInterface(cfg, config.WAN{ID: "l2", Proto: "l2tp", Interface: "if"}); got != "ppp-l2" {
		t.Fatalf("l2tp=%q", got)
	}
	if got := wanInterface(cfg, config.WAN{ID: "static", Proto: "static", Interface: "if"}); got != "eth9" {
		t.Fatalf("static=%q", got)
	}
}

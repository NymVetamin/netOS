package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// A channel's far end (a VPN provider, or the netOS behind a client exit) may
// send packets into the tunnel. They used to land in the VPN zone, whose
// default policy accepts everything to the router and into the LAN.
func TestChannelsAreJudgedAsInternet(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "wan", Name: "eth0"}, {ID: "lan", Name: "br-lan"}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan", Zone: "lan", Enabled: true, RouterAddress: "192.168.10.1/24"}}
	cfg.WANs = []config.WAN{{ID: "w", Interface: "wan", Proto: "dhcp", Enabled: true}}
	cfg.Channels = []config.Channel{
		{ID: "wg", Type: "wireguard", Index: 1, Enabled: true},
		{ID: "ike", Type: "ikev2", Index: 2, Enabled: true},
		{ID: "exit", Type: "wireguard", Index: 3, Enabled: true, WireGuardPeer: &config.WireGuardPeerChannel{ServerID: "s", PeerID: "p", ServerIndex: 1}},
	}
	cfg.VPNServers = []config.VPNServer{
		{ID: "s", Type: "wireguard", Index: 1, Enabled: true, Port: 51820, Subnet: "10.9.0.1/24", Peers: []config.VPNPeer{
			{ID: "phone", Enabled: true, Address: "10.9.0.2"},
			{ID: "p", Name: "exit", Enabled: true, Address: "10.9.0.3", UseAsChannel: true},
		}},
		{ID: "ike", Type: "ikev2", Index: 2, Enabled: true, Subnet: "10.11.0.1/24"},
	}
	rs, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	filter := rs.IPv4[strings.Index(rs.IPv4, "*filter"):]
	for _, want := range []string{
		"-A INPUT -i wg-ch1 -j WAN-IN\n",
		"-A FORWARD -i wg-ch1 -j WAN-FWD\n",
		"-A OUTPUT -o wg-ch1 -j WAN-OUT\n",
		"-A INPUT -i wg-srv1 -j VPN-IN\n",
		`-A VPN-IN -s 10.9.0.3/32 -i wg-srv1 -m comment --comment "выход через клиента «exit»" -j WAN-IN`,
		`-A VPN-FWD -s 10.9.0.3/32 -i wg-srv1 -m comment --comment "выход через клиента «exit»" -j WAN-FWD`,
	} {
		if !strings.Contains(filter, want) {
			t.Fatalf("missing %q in\n%s", want, filter)
		}
	}
	for _, bad := range []string{"-i wg-ch1 -j VPN-", "-i xfrm-ch2 -j VPN-", "-s 10.9.0.2/32 -i wg-srv1"} {
		if strings.Contains(filter, bad) {
			t.Fatalf("unexpected %q in\n%s", bad, filter)
		}
	}
	// The IKEv2 channel must be classified before the IPsec catch-all of the
	// server, and exactly once.
	jump := "-A INPUT -i xfrm-ch2 -j WAN-IN\n"
	ipsec := "-A INPUT -m policy --dir in --pol ipsec -j VPN-IN\n"
	if strings.Count(filter, jump) != 1 || strings.Index(filter, jump) > strings.Index(filter, ipsec) {
		t.Fatalf("IKEv2 channel jump order wrong:\n%s", filter)
	}

	// The exit side of the same scheme: the far router's clients arrive as new
	// connections and are accepted only when the administrator says so.
	accept := `-A WAN-FWD -i wg-ch1 -m comment --comment "транзит из канала «WG»" -j ACCEPT`
	cfg.Channels[0].Name = "WG"
	if rs, _ := Build(cfg); strings.Contains(rs.IPv4, accept) {
		t.Fatal("inbound transit accepted without the channel switch")
	}
	cfg.Channels[0].AcceptInbound = true
	rs, _ = Build(cfg)
	policy := `-A WAN-FWD -m comment --comment "политика зоны"`
	if !strings.Contains(rs.IPv4, accept) || strings.Index(rs.IPv4, accept) > strings.Index(rs.IPv4, policy) {
		t.Fatalf("inbound transit not accepted before the zone policy:\n%s", rs.IPv4)
	}
}

func TestPeerOnlyInternetChains(t *testing.T) {
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{Type: "wireguard", Index: 1, Enabled: true, Peers: []config.VPNPeer{{Enabled: true, UseAsChannel: true, Address: "10.9.0.3"}}}}
	for _, configured := range []bool{true, false} {
		if !configured {
			cfg.Firewall.Zones = cfg.Firewall.Zones[2:]
		}
		rs, _ := Build(cfg)
		expected := strings.Join(ExpectedChains(cfg), " ")
		for _, h := range hooks {
			chain := ChainName("wan", h.suffix)
			want := configured && h.flow != "out"
			if strings.Contains(rs.IPv4, ":"+chain+" ") != want || strings.Contains(expected, chain) != want {
				t.Fatalf("declaration %s", chain)
			}
			if h.flow == "out" {
				continue
			}
			target := "DROP"
			if configured {
				target = chain
			}
			for _, line := range strings.Split(rs.IPv4, "\n") {
				if strings.HasPrefix(line, "-A "+ChainName("vpn", h.suffix)+" -s 10.9.0.3/32 -i wg-srv1 ") && strings.HasSuffix(line, " -j "+target) {
					target = ""
					break
				}
			}
			if target != "" {
				t.Fatalf("missing %s jump to %s", h.builtin, target)
			}
		}
	}
}

func TestPeerChannelIgnoresInboundSwitch(t *testing.T) {
	cfg := config.Default()
	cfg.WANs = []config.WAN{{ID: "w", Proto: "pppoe", Enabled: true}}
	cfg.VPNServers = []config.VPNServer{{ID: "s", Type: "wireguard", Index: 1, Enabled: true, Peers: []config.VPNPeer{{ID: "p", Address: "10.9.0.3", Enabled: true, UseAsChannel: true}}}}
	cfg.Normalize()
	before, _ := Build(cfg)
	for i := range cfg.Channels {
		if cfg.Channels[i].WireGuardPeer != nil {
			cfg.Channels[i].AcceptInbound = true
		}
	}
	after, _ := Build(cfg)
	if after.IPv4 != before.IPv4 {
		t.Fatal("inapplicable switch changed firewall rules")
	}
}

func TestTunnelMSSFollowsInterfaceZone(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = []config.Channel{{Enabled: true, Type: "wireguard", Index: 2}, {Enabled: true, Type: "wireguard", WireGuardPeer: &config.WireGuardPeerChannel{ServerIndex: 1}}}
	for _, wan := range []bool{false, true} {
		for _, vpn := range []bool{false, true} {
			for i, z := range cfg.Firewall.Zones {
				switch z.Name {
				case "wan":
					cfg.Firewall.Zones[i].MSSClamp = wan
				case "vpn":
					cfg.Firewall.Zones[i].MSSClamp = vpn
				}
			}
			var b builder
			b.reducedPathMSS(cfg)
			for iface, on := range map[string]bool{"wg-ch2": wan, "wg-srv1": vpn} {
				for _, dir := range []string{"-i", "-o"} {
					if strings.Contains(b.String(), dir+" "+iface+" ") != on {
						t.Fatalf("wan=%v vpn=%v %s %s", wan, vpn, dir, iface)
					}
				}
			}
		}
	}
}

package firewall

import (
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestClientRestrictionsStayInsideForwardZones(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "lan", Name: "br0"}, {ID: "wan", Name: "eth0"}}
	c.Networks = []config.Network{{ID: "lan", Interface: "lan", Zone: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}
	c.WANs = []config.WAN{{ID: "wan", Interface: "wan", Enabled: true}}
	c.Clients = []config.Client{{MAC: "02:00:00:00:00:01", Blocked: true}, {MAC: "02:00:00:00:00:02", Channel: config.InternetBlockChannel}}
	c.VPNServers = []config.VPNServer{
		{ID: "oc", Type: "ocserv", Index: 2, Enabled: true, Subnet: "10.10.0.1/24", Peers: []config.VPNPeer{{Address: "10.10.0.2", Enabled: true, Channel: config.InternetBlockChannel}}},
		{ID: "ike", Type: "ikev2", Index: 3, Enabled: true, Subnet: "10.11.0.1/24", Peers: []config.VPNPeer{{Address: "10.11.0.2", Enabled: true, Channel: config.InternetBlockChannel}}},
	}
	c.IPv6.Mode = "passthrough"
	for _, enabled := range []bool{true, false} {
		c.Firewall.Enabled = enabled
		r, _ := Build(c)
		for _, rules := range []string{r.IPv4, r.IPv6} {
			filter := rules[strings.Index(rules, "*filter"):]
			for _, line := range strings.Split(filter, "\n") {
				if strings.HasPrefix(line, "-A FORWARD ") && (strings.Contains(line, "--mac-source") || strings.Contains(line, "10.10.0.2") || strings.Contains(line, "NETOS-INTERNET-BLOCK")) {
					t.Fatalf("client in built-in: %s", line)
				}
			}
			if !strings.Contains(filter, "-A LAN-FWD -m mac --mac-source 02:00:00:00:00:02") {
				t.Fatal("LAN restriction missing")
			}
		}
		filter := r.IPv4[strings.Index(r.IPv4, "*filter"):]
		for _, match := range []string{" -i vpns2+ -s 10.10.0.2/32", " -s 10.11.0.2/32 -m policy --dir in --pol ipsec"} {
			if !strings.Contains(filter, "-A VPN-FWD"+match) {
				t.Fatalf("missing VPN match: %s", match)
			}
			for _, chain := range []string{"LAN-FWD", "WAN-FWD", "NETOS-FWD-OTHER"} {
				if strings.Contains(filter, "-A "+chain+match) {
					t.Fatalf("VPN rule leaked to %s", chain)
				}
			}
		}
		ipsec := strings.Index(filter, "-A FORWARD -m policy --dir in --pol ipsec -j VPN-FWD")
		wan := strings.Index(filter, "-A FORWARD -i eth0 -j WAN-FWD")
		if ipsec < 0 || wan < 0 || ipsec > wan {
			t.Fatal("IPsec classified as physical WAN")
		}
		if enabled {
			for _, chain := range []string{"LAN-FWD", "VPN-FWD", "WAN-FWD", "NETOS-FWD-OTHER"} {
				for _, mac := range []string{"02:00:00:00:00:01", "02:00:00:00:00:02"} {
					check := strings.Index(filter, "-A "+chain+" -m mac --mac-source "+mac)
					global := strings.Index(filter, "-A "+chain+" -j NETOS-FWD-GLOBAL")
					if check < 0 || global < 0 || check > global {
						t.Fatalf("%s restriction after globals", chain)
					}
				}
			}
			if strings.Count(filter, "-A NETOS-FWD-GLOBAL -m conntrack --ctstate ESTABLISHED,RELATED") != 1 {
				t.Fatal("global state rule duplicated/lost")
			}
		}
	}
}

func BenchmarkVPNClientZoneRules(b *testing.B) {
	for _, count := range []int{10, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			c := config.Default()
			c.VPNServers = []config.VPNServer{{ID: "vpn", Type: "ocserv", Index: 1, Enabled: true, Subnet: "10.10.0.1/16"}}
			for i := 0; i < count; i++ {
				c.VPNServers[0].Peers = append(c.VPNServers[0].Peers, config.VPNPeer{Enabled: true, Address: fmt.Sprintf("10.10.%d.%d", i/254, i%254+1), Channel: config.InternetBlockChannel})
			}
			zones := buildZoneMap(c)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var out builder
				out.filter(c, zones)
			}
		})
	}
}

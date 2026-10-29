package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestL2TPWANAccessFollowsIPsecWithoutOverridingUserRules(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "wan", Name: "wan0", Enabled: true}}
	c.WANs = []config.WAN{{ID: "wan", Interface: "wan", Enabled: true, Proto: "dhcp"}}
	c.VPNServers = []config.VPNServer{{ID: "l2", Name: "L2", Type: "l2tp", Enabled: true, Index: 1, Port: 1701, Config: map[string]any{"listen": "0.0.0.0"}}}
	for _, secured := range []bool{true, false, false, true} {
		c.VPNServers[0].Config["ipsec"] = secured
		for _, manual := range []bool{false, true} {
			c.Firewall.Rules = []config.FirewallRule{{ID: "manual", Name: "manual-l2tp", Enabled: manual, Zone: "wan", Flow: "in", Protocol: "udp", DstPort: "1701", Action: "accept"}}
			out, err := Build(c)
			if err != nil {
				t.Fatal(err)
			}
			auto := 0
			user := 0
			for _, line := range strings.Split(out.IPv4, "\n") {
				if (strings.Contains(line, "--dport 1701") || strings.Contains(line, "--dports 1701")) && strings.HasSuffix(line, "-j ACCEPT") {
					if strings.Contains(line, "manual-l2tp") {
						user++
					} else {
						auto++
					}
				}
			}
			if (auto == 1) != secured || auto > 1 || (user == 1) != manual {
				t.Fatalf("secured=%v manual=%v auto=%d user=%d", secured, manual, auto, user)
			}
			if strings.Contains(out.IPv4, ":NETOS-L2TP-IPSEC ") != secured {
				t.Fatal("incorrect IPsec guard")
			}
			if !secured && strings.Contains(out.IPv4, "--dport 1701 -j DROP") {
				t.Fatal("added plaintext port deny")
			}
			if c.Firewall.Rules[0].Enabled != manual {
				t.Fatal("modified user rule")
			}
		}
	}
}

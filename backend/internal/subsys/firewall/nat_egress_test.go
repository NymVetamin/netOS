package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestSystemNATFollowsEgressWithoutChangingDesiredState(t *testing.T) {
	for _, kind := range []string{"wan", "pppoe", "wireguard", "xray", "openconnect", "l2tp", "ikev2"} {
		t.Run(kind, func(t *testing.T) {
			c := config.Default()
			c.WANs = nil
			c.Channels = nil
			c.Interfaces = []config.Interface{{ID: "port", Name: "eth-test", Enabled: true}}
			iface := "eth-test"
			if kind == "wan" || kind == "pppoe" {
				c.WANs = []config.WAN{{ID: "uplink", Name: "test", Interface: "port", Proto: kind}}
				if kind == "pppoe" {
					iface = "ppp-uplink"
				}
			} else {
				c.Channels = []config.Channel{{ID: "test", Name: "test", Type: kind, Index: 1}}
				switch kind {
				case "wireguard":
					iface = "wg-ch1"
				case "l2tp":
					iface = "ppp-ch1"
				case "ikev2":
					iface = "xfrm-ch1"
				default:
					iface = "tun-ch1"
				}
			}
			c.Firewall.NAT = []config.NATRule{{ID: "nat-wan", System: true, Enabled: true, Direction: "source", Interface: iface}}
			for _, enabled := range []bool{true, false, false, true} {
				if len(c.WANs) > 0 {
					c.WANs[0].Enabled = enabled
				} else {
					c.Channels[0].Enabled = enabled
				}
				for _, nat := range []bool{true, false} {
					c.Firewall.NAT[0].Enabled = nat
					out, err := Build(c)
					if err != nil {
						t.Fatal(err)
					}
					got := strings.Contains(out.IPv4, "-A POSTROUTING -o "+iface+" ")
					if got != (enabled && nat) {
						t.Fatalf("egress=%v NAT=%v: generated=%v", enabled, nat, got)
					}
					if c.Firewall.NAT[0].Enabled != nat {
						t.Fatal("saved NAT switch mutated")
					}
				}
			}
		})
	}
}

func TestDisabledWANPreservesExplicitNATAndSharedEgress(t *testing.T) {
	c := config.Default()
	c.Channels = nil
	c.Interfaces = []config.Interface{{ID: "port", Name: "eth0", Enabled: true}}
	c.WANs = []config.WAN{{ID: "off", Interface: "port", Enabled: false}}
	for _, rule := range []config.NATRule{
		{Enabled: true, Interface: "eth0"},
		{Enabled: true, System: true, Interface: "eth0", ToSource: "192.0.2.2"},
		{Enabled: true, System: true, Interface: "other"},
	} {
		c.Firewall.NAT = []config.NATRule{rule}
		out, _ := Build(c)
		if !strings.Contains(out.IPv4, "-A POSTROUTING -o "+rule.Interface+" ") {
			t.Fatal("independent NAT removed", rule)
		}
	}
	c.Firewall.NAT = []config.NATRule{{System: true, Enabled: true, Interface: "eth0"}}
	c.WANs = append(c.WANs, config.WAN{ID: "on", Interface: "port", Enabled: true})
	out, _ := Build(c)
	if strings.Count(out.IPv4, "-A POSTROUTING -o eth0 ") != 1 {
		t.Fatal("shared active egress lost or duplicated NAT")
	}
}

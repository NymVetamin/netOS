package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestSocksAccessPrecedesGeneralAccept(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "lan", Name: "br-lan", Enabled: true}, {ID: "wan", Name: "eth0", Enabled: true}}
	c.Networks = []config.Network{{ID: "lan", Interface: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}
	c.WANs = []config.WAN{{ID: "wan", Interface: "wan", Enabled: true}}
	c.Socks = config.Socks{Enabled: true, Port: 1080, Networks: []string{"lan"}}
	for _, wan := range []bool{false, true} {
		c.Socks.AllowWAN = wan
		rules, err := Build(c)
		if err != nil {
			t.Fatal(err)
		}
		text := rules.IPv4
		allow := strings.Index(text, "-A INPUT -i br-lan -s 192.0.2.0/24 -p tcp --dport 1080")
		deny := strings.Index(text, "-A INPUT -p tcp --dport 1080")
		if allow < 0 || deny <= allow {
			t.Fatal("missing/late ACL")
		}
		if strings.Contains(text, "-A INPUT -i eth0 -p tcp --dport 1080") != wan {
			t.Fatal("WAN scope mismatch")
		}
		if strings.Contains(text, "-p udp --dport 1080") {
			t.Fatal("TCP proxy must not change access to an unrelated UDP service")
		}
	}
}

func TestSocksVPNScopes(t *testing.T) {
	c := config.Default()
	c.Socks = config.Socks{Enabled: true, Port: 1080, VPNs: []string{"wg", "ike"}}
	c.VPNServers = []config.VPNServer{
		{ID: "wg", Type: "wireguard", Enabled: true, Index: 1, Subnet: "10.9.0.1/24"},
		{ID: "ike", Type: "ikev2", Enabled: true, Index: 2, Subnet: "10.10.0.1/24"},
	}
	rules, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-s 10.9.0.0/24 -p tcp --dport 1080", "-m policy --dir in --pol ipsec -s 10.10.0.0/24 -p tcp --dport 1080"} {
		if !strings.Contains(rules.IPv4, want) {
			t.Fatal(want)
		}
	}
}

func TestSocksIPv6CannotBypassScopes(t *testing.T) {
	c := config.Default()
	c.IPv6.Mode = "passthrough"
	c.Socks = config.Socks{Enabled: true, Port: 1080}
	rules := buildIPv6(c)
	if !strings.Contains(rules, "-A INPUT -p tcp --dport 1080 -j DROP") {
		t.Fatal(rules)
	}
	c.Socks.Enabled = false
	if strings.Contains(buildIPv6(c), "--dport 1080") {
		t.Fatal("disabled proxy leaves IPv6 rules")
	}
}

package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestIPTVScopeAndOutputPolicy(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "up", Name: "eth0.20"}, {ID: "lan", Name: "br0"}, {ID: "other", Name: "br1"}}
	c.WANs = []config.WAN{{ID: "wan", Interface: "up", Enabled: true, Proto: "dhcp"}}
	c.Networks = []config.Network{{ID: "lan", Interface: "lan", Enabled: true, RouterAddress: "10.99.0.1/24"}, {ID: "other", Interface: "other", Enabled: true, RouterAddress: "10.98.0.1/24"}}
	c.IPTV = config.IPTV{Enabled: true, Upstream: "wan", Networks: []string{"lan"}, Sources: []string{"192.0.2.0/24"}}
	b := &builder{}
	b.iptvAccess(c)
	text := b.String()
	if !strings.Contains(text, "-i eth0.20 -o br0 -s 192.0.2.0/24 -p udp -m iprange --dst-range 224.0.1.0-239.255.255.255") || strings.Contains(text, "br1") || strings.Contains(text, "OUTPUT") {
		t.Fatal(text)
	}
	c.Firewall.OutputPolicy = "drop"
	b = &builder{}
	b.iptvAccess(c)
	if strings.Count(b.String(), "-A OUTPUT") != 2 {
		t.Fatal("missing IGMP output", b.String())
	}
	c.IPTV.Sources = nil
	b = &builder{}
	b.iptvAccess(c)
	if strings.Contains(b.String(), "-s 0.0.0.0/0") {
		t.Fatal("iptables-save omits the all-source selector", b.String())
	}
	c.IPTV.Enabled = false
	b = &builder{}
	b.iptvAccess(c)
	if b.String() != "" {
		t.Fatal("disabled IPTV kept permits")
	}
}

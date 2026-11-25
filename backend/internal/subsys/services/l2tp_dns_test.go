package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestL2TPDynamicDNSListener(t *testing.T) {
	c := config.Default()
	c.DNS.Enabled, c.DNS.Provider = true, "dnsmasq"
	c.VPNServers = []config.VPNServer{{Type: "l2tp", Index: 2, Enabled: true, Subnet: "10.99.0.1/24"}, {Type: "l2tp", Index: 20, Enabled: false}}
	if got := NewDnsmasq(nil).Render(c); !strings.Contains(got, "interface=pp2-*\n") || strings.Contains(got, "interface=pp20-*\n") {
		t.Fatalf("wrong listeners: %v", got)
	}
	for _, provider := range []string{"unbound", "dnsproxy"} {
		c.DNS.Provider = provider
		if !DNSFrontendNeeded(c) {
			t.Fatalf("missing dynamic frontend for %s", provider)
		}
		for _, n := range dnsListenNetworks(c) {
			if n.address == "10.99.0.1" {
				t.Fatal("binding an address before PPP connection")
			}
		}
	}
}

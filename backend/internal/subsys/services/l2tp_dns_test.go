package services

import (
	"github.com/netos-router/netos/internal/config"
	"slices"
	"testing"
)

func TestL2TPDynamicDNSListener(t *testing.T) {
	c := config.Default()
	c.DNS.Enabled = true
	c.VPNServers = []config.VPNServer{{Type: "l2tp", Index: 2, Enabled: true, Subnet: "10.99.0.1/24"}, {Type: "l2tp", Index: 20, Enabled: false}}
	if got := dnsListenInterfaces(c); !slices.Contains(got, "pp2-*") || slices.Contains(got, "pp20-*") {
		t.Fatalf("wrong listeners: %v", got)
	}
	for _, provider := range []string{"unbound", "dnsproxy"} {
		c.DNS.Provider = provider
		if !dnsFrontendNeeded(c) {
			t.Fatalf("missing dynamic frontend for %s", provider)
		}
		for _, n := range dnsListenNetworks(c) {
			if n.address == "10.99.0.1" {
				t.Fatal("binding an address before PPP connection")
			}
		}
	}
}

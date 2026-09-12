package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestDnsmasqAcceptsDynamicOcservInterfaces(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Enabled, cfg.DNS.Provider = true, "dnsmasq"
	cfg.VPNServers = []config.VPNServer{
		{ID: "enabled", Type: "ocserv", Index: 3, Enabled: true},
		{ID: "disabled", Type: "ocserv", Index: 7},
	}
	rendered := NewDnsmasq(nil).Render(cfg)
	if !strings.Contains(rendered, "\ninterface=vpns3*\n") || !strings.Contains(rendered, "\nbind-dynamic\n") {
		t.Fatalf("new ocserv workers would not be accepted: %s", rendered)
	}
	if strings.Contains(rendered, "interface=vpns7") || strings.Contains(rendered, "interface=vpns*\n") {
		t.Fatalf("disabled or unrelated servers exposed: %s", rendered)
	}
	cfg.VPNServers = nil
	if strings.Contains(NewDnsmasq(nil).Render(cfg), "interface=vpns") {
		t.Fatal("removed ocserv server left a DNS listener")
	}
}

func TestOcservDNSFrontendAllProviders(t *testing.T) {
	for _, provider := range []string{"unbound", "dnsproxy"} {
		t.Run(provider, func(t *testing.T) {
			cfg := dnsDomainPolicyConfig(provider)
			cfg.Policies = nil
			cfg.VPNServers = []config.VPNServer{{ID: "oc", Type: "ocserv", Index: 3, Enabled: true}}
			front := NewDnsmasq(nil).Render(cfg)
			if !NewDnsmasq(nil).Needed(cfg) || !strings.Contains(front, "interface=vpns3*") || !strings.Contains(front, "server=127.0.0.1#5355") {
				t.Fatalf("VPN clients have no dynamic DNS listener: %s", front)
			}
			if strings.Contains(front, "ipset=/") || strings.Contains(front, "max-ttl=") {
				t.Fatalf("VPN-only frontend enabled domain policy behavior: %s", front)
			}
			backend := NewUnbound(nil).Render(cfg)
			want := "port: 5355"
			if provider == "dnsproxy" {
				backend, want = NewDnsproxy(nil).Render(cfg), "  - 5355"
			}
			if !strings.Contains(backend, want) || strings.Contains(backend, "192.168.50.1") {
				t.Fatalf("backend conflicts with frontend: %s", backend)
			}
			cfg.VPNServers[0].Enabled = false
			if dnsFrontendNeeded(cfg) || NewDnsmasq(nil).Needed(cfg) {
				t.Fatal("disabled VPN retained an unnecessary frontend")
			}
		})
	}
}

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

package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestIsolationEmptyAndProxyDestinationToggle(t *testing.T) {
	cfg := config.Default()
	cfg.Networks = []config.Network{{ID: "lan", Name: "LAN", Zone: "lan", Enabled: true, RouterAddress: "192.168.10.1/24"}}
	cfg.VPNServers = []config.VPNServer{{ID: "proxy", Type: "xray", Enabled: true, Name: "Proxy", Subnet: "10.50.0.1/24"}}
	render := func() string { var b builder; b.isolation(cfg); return b.String() }
	if got := render(); got != "" {
		t.Fatalf("unisolated produced rules: %s", got)
	}
	cfg.VPNServers[0].Isolated = true
	first := render()
	if !strings.Contains(first, "-A LAN-ISOLATION -s 192.168.10.0/24 -d 10.50.0.0/24") {
		t.Fatalf("isolated proxy not protected: %s", first)
	}
	if strings.Contains(first, "-A FORWARD -s 10.50.0.0/24") {
		t.Fatal("proxy used as forwarded source")
	}
	cfg.VPNServers[0].Isolated = false
	if got := render(); got != "" {
		t.Fatalf("stale isolation: %s", got)
	}
	cfg.VPNServers[0].Isolated = true
	if got := render(); got != first {
		t.Fatal("re-enabling isolation changed rules")
	}
	cfg.VPNServers[0].Enabled = false
	if got := render(); got != "" {
		t.Fatal("disabled isolated server generated rules")
	}
}

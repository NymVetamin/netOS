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

func TestIsolationSkipsEqualIDsBeforeLinkingSource(t *testing.T) {
	cfg := config.Default()
	cfg.VPNServers = nil
	cfg.Networks = []config.Network{
		{ID: "dup", Enabled: true, Zone: "lan", Isolated: true, RouterAddress: "192.0.2.1/24"},
		{ID: "dup", Enabled: true, Zone: "lan", RouterAddress: "198.51.100.1/24"},
	}
	var empty builder
	empty.isolation(cfg)
	if empty.String() != "" {
		t.Fatalf("equal IDs created a chain: %s", empty.String())
	}
	cfg.Networks = append(cfg.Networks, config.Network{ID: "other", Enabled: true, Zone: "lan", RouterAddress: "203.0.113.1/24"})
	var rules builder
	rules.isolation(cfg)
	text := rules.String()
	if strings.Count(text, ":LAN-ISOLATION ") != 1 || strings.Count(text, "-A FORWARD ") != 2 ||
		strings.Contains(text, "198.51.100.0/24") || strings.Count(text, "-j REJECT") != 2 {
		t.Fatalf("unexpected links or pairs: %s", text)
	}
}

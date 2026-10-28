package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestPanelRedirectPreservesFirewallScope(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan-if", Name: "br-test", Enabled: true, Type: "bridge"}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan-if", RouterAddress: "192.0.2.1/24", Zone: "lan", Enabled: true}}
	idx := -1
	for i := range cfg.Firewall.Rules {
		if cfg.Firewall.Rules[i].ID == config.RulePanel {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("missing panel rule")
	}
	rule := &cfg.Firewall.Rules[idx]
	rule.Zone = "lan"
	rule.SrcIP = "192.0.2.0/25"
	rule.Interface = "br-test"
	for _, port := range []int{8443, 9443, 80} {
		cfg.System.Panel.Port = port
		cfg.Normalize()
		rules, err := Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		lines := []string{}
		for _, line := range strings.Split(rules.IPv4, "\n") {
			if strings.Contains(line, "Веб-панель netOS") {
				lines = append(lines, line)
			}
		}
		if len(lines) != 1 || !strings.Contains(lines[0], "-A LAN-IN") || !strings.Contains(lines[0], "-i br-test") || !strings.Contains(lines[0], "-s 192.0.2.0/25") {
			t.Fatalf("scope changed: %v", lines)
		}
		want := "--dports " + config.PanelPorts(port)
		if !strings.Contains(lines[0], want) {
			t.Fatalf("ports: %s", lines[0])
		}
	}
	cfg.Firewall.Rules[idx].Enabled = false
	rules, _ := Build(cfg)
	if strings.Contains(rules.IPv4, "Веб-панель netOS") {
		t.Fatal("disabled panel reopened")
	}
	cfg.Firewall.Rules[idx].Enabled = true
	cfg.Firewall.Rules[idx].Action = "drop"
	rules, _ = Build(cfg)
	for _, line := range strings.Split(rules.IPv4, "\n") {
		if strings.Contains(line, "Веб-панель netOS") && !strings.HasSuffix(line, "-j DROP") {
			t.Fatal(line)
		}
	}
}

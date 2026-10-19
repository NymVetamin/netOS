package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestPreviewSavedRuleIdentity(t *testing.T) {
	var cfg config.Config
	cfg.Firewall.Enabled = true
	cfg.Firewall.Rules = []config.FirewallRule{
		{ID: "first", Name: "same name", Enabled: true, Zone: "global", Flow: "in", Action: "accept", Log: true},
		{ID: "second", Name: "same name", Enabled: true, Zone: "global", Flow: "in", Action: "accept"},
		{ID: "disabled", Name: "disabled", Zone: "global", Flow: "in", Action: "drop"},
	}
	rules, err := Build(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for line, ids := range rules.RuleIDs {
		if !strings.Contains(rules.IPv4, line+"\n") {
			t.Fatalf("metadata changed command: %s", line)
		}
		for _, id := range ids {
			counts[id]++
		}
	}
	if counts["first"] != 1 || counts["second"] != 1 || counts["disabled"] != 0 {
		t.Fatal(counts)
	}
	for _, ids := range rules.RuleIDs {
		if len(ids) == 2 && ids[0] == "first" && ids[1] == "second" {
			return
		}
	}
	t.Fatal("identical command occurrences lost their IDs")
}

func TestPreviewNATIdentity(t *testing.T) {
	var cfg config.Config
	cfg.Firewall.Enabled = true
	cfg.Firewall.NAT = []config.NATRule{
		{ID: "snat", Name: "same", Enabled: true, Direction: "source", Interface: "eth0"},
		{ID: "dnat", Name: "same", Enabled: true, Direction: "destination", Protocol: "tcpudp", ExtPort: "8080", DestIP: "192.0.2.2"},
		{ID: "disabled", Name: "same", Direction: "source", Interface: "eth0"},
	}
	rules, err := Build(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for line, ids := range rules.RuleIDs {
		if !strings.Contains(rules.IPv4, line+"\n") {
			t.Fatalf("metadata altered command: %s", line)
		}
		for _, id := range ids {
			counts[id]++
			if id == "snat" && !strings.HasPrefix(line, "-A POSTROUTING ") || id == "dnat" && !strings.HasPrefix(line, "-A PREROUTING ") {
				t.Fatalf("wrong NAT metadata: %s %s", id, line)
			}
		}
	}
	if counts["snat"] != 1 || counts["dnat"] != 2 || counts["disabled"] != 0 {
		t.Fatal(counts)
	}
}

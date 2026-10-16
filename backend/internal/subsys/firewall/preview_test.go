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

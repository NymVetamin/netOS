package config

import (
	"encoding/json"
	"testing"
)

func TestRemovedDefaultRulesSurviveNormalizeAndReload(t *testing.T) {
	c := Default()
	c.Firewall.RemovedDefaults = []string{RuleSSH, RuleLoopback, RulePanel}
	kept := c.Firewall.Rules[:0]
	for _, r := range c.Firewall.Rules {
		if r.ID != RuleSSH && r.ID != RuleLoopback && r.ID != RulePanel {
			kept = append(kept, r)
		}
	}
	c.Firewall.Rules = kept
	c.Normalize()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Config
	if err = json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	loaded.Normalize()
	loaded.EnsureSystemRules()
	for _, r := range loaded.Firewall.Rules {
		if r.ID == RuleSSH || r.ID == RuleLoopback || r.ID == RulePanel {
			t.Fatalf("deleted rule restored: %s", r.ID)
		}
	}
	if len(loaded.Firewall.Rules) == 0 {
		t.Fatal("unrelated defaults lost")
	}
}
func TestRemovedDefaultsDoNotSuppressACMEOrLegacyDefaults(t *testing.T) {
	c := Default()
	c.Firewall.Rules = nil
	c.EnsureSystemRules()
	if len(c.Firewall.Rules) == 0 {
		t.Fatal("legacy defaults missing")
	}
	c.System.Panel.TLS.Mode = "acme"
	c.Firewall.RemovedDefaults = []string{RuleACME}
	c.EnsureSystemRules()
	for _, r := range c.Firewall.Rules {
		if r.ID == RuleACME {
			return
		}
	}
	t.Fatal("ACME suppressed by deleted starter rule list")
}

package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRemovedDefaultRulesSurviveNormalizeAndReload(t *testing.T) {
	c := Default()
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
func TestEmptyRulesStayEmptyButACMEStillManaged(t *testing.T) {
	c := Default()
	if len(c.Firewall.Rules) == 0 {
		t.Fatal("initial rules missing")
	}
	c.Firewall.Rules = nil
	c.Normalize()
	c.EnsureSystemRules()
	if len(c.Firewall.Rules) != 0 {
		t.Fatal("empty user rules were restored")
	}
	c.System.Panel.TLS.Mode = "acme"
	c.Normalize()
	if len(c.Firewall.Rules) != 1 || c.Firewall.Rules[0].ID != RuleACME {
		t.Fatal("ACME must be the only generated rule")
	}
	c.System.Panel.TLS.Mode = "selfsigned"
	c.Normalize()
	if len(c.Firewall.Rules) != 0 {
		t.Fatal("ACME removal restored user rules")
	}
}
func TestOldDeletionMetadataIsDiscarded(t *testing.T) {
	c := Default()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	fw := data["firewall"].(map[string]any)
	fw["rules"] = []any{}
	fw["removed_defaults"] = []string{RuleSSH}
	raw, err = json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Config
	if err = json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	loaded.Normalize()
	raw, err = json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Firewall.Rules) != 0 || bytes.Contains(raw, []byte("removed_defaults")) {
		t.Fatal("old metadata retained or deleted rules restored")
	}
}
func TestExistingPanelRuleAndDisabledSSH(t *testing.T) {
	c := Default()
	c.System.Panel.Port = 9443
	for i := range c.Firewall.Rules {
		if c.Firewall.Rules[i].ID == RuleSSH {
			c.Firewall.Rules[i].Enabled = false
			c.Firewall.Rules[i].SrcIP = "192.0.2.0/24"
		}
	}
	c.Normalize()
	for _, r := range c.Firewall.Rules {
		if r.ID == RulePanel && r.DstPort != "80,9443" {
			t.Fatal("panel port not synchronized")
		}
		if r.ID == RuleSSH && (r.Enabled || r.SrcIP != "192.0.2.0/24") {
			t.Fatal("disabled SSH modified")
		}
	}
}

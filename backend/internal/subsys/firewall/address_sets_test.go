package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/policy"
)

func TestFirewallSetSelectorsApplyToBothSides(t *testing.T) {
	cfg := config.Default()
	cfg.Firewall.IPSets = []config.FirewallIPSet{{ID: "sources", Name: "Sources"}, {ID: "destinations", Name: "Destinations"}}
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, config.FirewallRule{ID: "qa", Enabled: true, Zone: "global", Flow: "forward", Action: "drop", SrcIPSet: "sources", DstIPSet: "destinations"})
	rs, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := "-m set --match-set " + policy.FirewallSetName("sources") + " src -m set --match-set " + policy.FirewallSetName("destinations") + " dst"
	if !strings.Contains(rs.IPv4, want) {
		t.Fatal("set selectors missing")
	}
}

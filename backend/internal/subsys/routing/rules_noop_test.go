package routing

import (
	"context"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestUnchangedRulesAreNotRecreated(t *testing.T) {
	cfg := config.Default()
	cfg.Routing.Tables = []config.RouteTable{{Name: "qa", Number: 200}}
	cfg.Routing.Rules = []config.RouteRule{{Enabled: true, Priority: 20100, From: "192.0.2.1/32", FwMark: "16/255", Table: "qa"}}
	r := &recordingRunner{responses: map[string]runnerResponse{"ip -4 rule show": {out: "0: from all lookup local\n20100: from 192.0.2.1 fwmark 0x10/0xff lookup 200\n32766: from all lookup main\n"}}}
	if err := New(r).applyRules(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(r.commands) != 1 {
		t.Fatalf("unchanged rules rewritten: %s", commandStrings(r.commands))
	}
}

func TestRuleComparisonRetainsRepairForDifferences(t *testing.T) {
	cfg := config.Default()
	cfg.Routing.Rules = []config.RouteRule{{Enabled: true, Priority: 20100, Table: "main"}}
	for _, out := range []string{
		"", "20100: from 192.0.2.1 lookup main", "20100: from all lookup 200",
		"20101: from all lookup main", "20100: from all iif eth0 lookup main",
		"20100: from all lookup main suppress_prefixlength 0",
		"20100: not from all lookup main", "20100: from all fwmark 1 lookup main",
		"20100: from all lookup main\n20100: from all lookup main",
		"20100: from all lookup main\n20200: from all lookup 200",
	} {
		if rulesAlreadyApplied(out, cfg) {
			t.Fatalf("difference ignored: %q", out)
		}
	}
	if !rulesAlreadyApplied("20100: from all lookup 254", cfg) {
		t.Fatal("builtin table alias not normalized")
	}
	cfg.Routing.Rules = append(cfg.Routing.Rules, cfg.Routing.Rules[0])
	if rulesAlreadyApplied("20100: from all lookup main\n20100: from all lookup main", cfg) {
		t.Fatal("ambiguous duplicate order skipped")
	}
}

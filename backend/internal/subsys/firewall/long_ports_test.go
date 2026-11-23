package firewall

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestLongPortListsRenderWithinKernelLimit(t *testing.T) {
	ports := make([]string, 300)
	for i := range ports {
		ports[i] = strconv.Itoa(1000 + 2*i)
	}
	spec := strings.Join(ports, ",")
	var b builder
	b.emitRule("OUTPUT", config.FirewallRule{ID: "measure", Name: "measure", Flow: "out", Action: "continue", Protocol: "udp", SrcPort: spec, DstPort: spec, Log: true}, "")
	cfg := config.Default()
	cfg.Policies = []config.Policy{{ID: "p", Name: "p", Enabled: true, Channel: "direct", Protocol: "udp", DstPort: spec}}
	b.channelPolicies(cfg)
	if len(b.ruleIDs) != 1 || strings.Count(b.String(), " -j LOG ") != 1 {
		t.Fatal("logging or rule counters duplicated")
	}
	lines := strings.Split(b.String(), "\n")
	if len(lines) > 120 {
		t.Fatalf("two long selectors expanded to %d lines", len(lines))
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		for i, v := range fields {
			if v == "--dports" || v == "--sports" {
				ports := fields[i+1]
				if 1+strings.Count(ports, ",")+strings.Count(ports, ":") > 15 {
					t.Fatalf("oversize multiport: %s", ports)
				}
			}
		}
	}
}

func TestMultiportSlotBoundaries(t *testing.T) {
	full := strings.Repeat("80,", 14) + "80"
	ranges := strings.Repeat("20-25,", 7)
	wantRanges := strings.Repeat("20:25,", 7)
	for _, tc := range []struct {
		spec, inline string
		groups       []string
	}{
		{"", "", nil},
		{" 00025-25 , 00443 ", "25,443", nil},
		{full, full, nil},
		{full + ",81", "", []string{full, "81"}},
		{ranges + "30", wantRanges + "30", nil},
		{ranges + "24-26", "", []string{strings.TrimSuffix(wantRanges, ","), "24:26"}},
	} {
		inline, groups := splitPortMatch(tc.spec)
		if inline != tc.inline || !slices.Equal(groups, tc.groups) {
			t.Errorf("splitPortMatch(%q) = %q, %v; want %q, %v", tc.spec, inline, groups, tc.inline, tc.groups)
		}
	}
}

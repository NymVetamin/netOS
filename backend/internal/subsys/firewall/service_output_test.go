package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestServiceOutputExceptionsOnlyWhenOutputRestricted(t *testing.T) {
	var inputBaseline string
	for _, tc := range []struct {
		name, policy, flow, action, zone string
		enabled, want                    bool
	}{
		{name: "accept", policy: "accept"},
		{name: "legacy default"},
		{name: "drop", policy: "drop", want: true},
		{name: "reject", policy: "reject", want: true},
		{name: "global deny", policy: "accept", flow: "out", action: "drop", zone: "global", enabled: true, want: true},
		{name: "zone deny", policy: "accept", flow: "out", action: "reject", zone: "lan", enabled: true, want: true},
		{name: "all directions deny", policy: "accept", flow: "any", action: "drop", zone: "global", enabled: true, want: true},
		{name: "disabled deny", policy: "accept", flow: "out", action: "drop", zone: "global"},
		{name: "input deny", policy: "accept", flow: "in", action: "drop", zone: "global", enabled: true},
		{name: "forward deny", policy: "accept", flow: "forward", action: "reject", zone: "global", enabled: true},
		{name: "manual accept", policy: "accept", flow: "out", action: "accept", zone: "global", enabled: true},
		{name: "manual counter", policy: "accept", flow: "out", action: "continue", zone: "global", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := config.Default()
			c.Firewall.OutputPolicy = tc.policy
			c.Interfaces = []config.Interface{{ID: "lanif", Name: "eth1", Enabled: true}}
			c.Networks = []config.Network{{ID: "lan", Enabled: true, Interface: "lanif", RouterAddress: "192.0.2.1/24", Zone: "lan"}}
			c.Samba = config.Samba{Enabled: true, Discovery: true, Networks: []string{"lan"}}
			c.Socks = config.Socks{Enabled: true, Port: 1080, Networks: []string{"lan"}}
			if tc.flow != "" {
				c.Firewall.Rules = append(c.Firewall.Rules, config.FirewallRule{ID: "manual", Name: "manual", Enabled: tc.enabled, Flow: tc.flow, Action: tc.action, Zone: tc.zone, Protocol: "tcp", DstPort: "443"})
			}
			var b builder
			b.sambaAccess(c)
			b.socksAccess(c)
			input := ""
			outputs := []string{}
			for _, line := range strings.Split(b.String(), "\n") {
				if strings.HasPrefix(line, "-A INPUT ") {
					input += line + "\n"
				}
				if strings.HasPrefix(line, "-A OUTPUT ") {
					outputs = append(outputs, line)
				}
			}
			if inputBaseline == "" {
				inputBaseline = input
			}
			if input != inputBaseline {
				t.Fatal("service access restrictions changed")
			}
			wantCount := 0
			if tc.want {
				wantCount = 6
			}
			if len(outputs) != wantCount {
				t.Fatalf("got %d service output rules, want %d: %v", len(outputs), wantCount, outputs)
			}
			rules, err := Build(c)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range outputs {
				if !strings.Contains(rules.IPv4, line) {
					t.Fatalf("lost exception: %s", line)
				}
				if tc.enabled && tc.flow == "out" && strings.Index(rules.IPv4, line) > strings.Index(rules.IPv4, `--comment "manual"`) {
					t.Fatal("exception moved after manual rule")
				}
			}
			if tc.enabled && !strings.Contains(rules.IPv4, `--comment "manual"`) {
				t.Fatal("manual rule lost")
			}
		})
	}
}

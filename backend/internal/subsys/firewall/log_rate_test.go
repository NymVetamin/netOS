package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestLoggingRateLimitDoesNotLimitFirewallAction(t *testing.T) {
	for _, action := range []string{"accept", "drop", "reject", "continue"} {
		t.Run(action, func(t *testing.T) {
			var b builder
			b.emitRule("INPUT", config.FirewallRule{
				Name: "bounded log", Log: true, Action: action,
				Protocol: "udp", DstPort: "53",
			}, "")
			lines := strings.Split(strings.TrimSpace(b.String()), "\n")
			if len(lines) != 2 {
				t.Fatalf("expected separate logging and action rules: %s", b.String())
			}
			if !strings.Contains(lines[0], " -m limit --limit 5/sec --limit-burst 10 -j LOG ") {
				t.Fatalf("logging has no bounded rate: %s", lines[0])
			}
			if strings.Contains(lines[1], "limit") {
				t.Fatalf("exhausting log allowance changes packet filtering: %s", lines[1])
			}
			if action == "continue" {
				if strings.Contains(lines[1], " -j ") {
					t.Fatalf("continue must still reach the next rule: %s", lines[1])
				}
			} else if !strings.HasSuffix(lines[1], "-j "+target(action)) {
				t.Fatalf("packet action changed: %s", lines[1])
			}
		})
	}
}

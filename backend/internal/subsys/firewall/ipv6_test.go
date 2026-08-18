package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIPv6PassthroughProducesClearingRuleset(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	rules := buildIPv6(cfg)
	for _, policy := range []string{"INPUT ACCEPT", "FORWARD ACCEPT", "OUTPUT ACCEPT"} {
		if !strings.Contains(rules, policy) {
			t.Fatalf("разрешающий ruleset не содержит %q:\n%s", policy, rules)
		}
	}
	if strings.Contains(rules, " DROP ") {
		t.Fatalf("passthrough оставляет DROP:\n%s", rules)
	}
}

package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestRuleInterfaceUsesDirectionAppropriateSelector(t *testing.T) {
	in := selectors(config.FirewallRule{Flow: "in", Interface: "eth0"})
	out := selectors(config.FirewallRule{Flow: "out", Interface: "eth0"})
	if !strings.Contains(in, " -i eth0") || strings.Contains(in, " -o eth0") {
		t.Fatalf("inbound selector is wrong: %q", in)
	}
	if !strings.Contains(out, " -o eth0") || strings.Contains(out, " -i eth0") {
		t.Fatalf("outbound selector is wrong: %q", out)
	}
}

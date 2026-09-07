package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestConnectionStateWhitespaceAcceptedByValidationRendersSafely(t *testing.T) {
	for _, value := range []string{"new, established", " new , established ", "NEW,\tRELATED", "invalid"} {
		t.Run(value, func(t *testing.T) {
			rule := config.FirewallRule{Flow: "forward", ConnState: value}
			got := selectors(rule)
			parts := strings.Fields(got)
			if len(parts) != 4 || parts[0] != "-m" || parts[1] != "conntrack" || parts[2] != "--ctstate" {
				t.Fatalf("state list must remain a single argument: %q", got)
			}
			for _, state := range strings.Split(parts[3], ",") {
				if state != "NEW" && state != "ESTABLISHED" && state != "RELATED" && state != "INVALID" {
					t.Fatalf("invalid emitted state %q from %q", state, value)
				}
			}
		})
	}
}

func TestPortListWhitespaceAcceptedByValidationRendersSafely(t *testing.T) {
	for value, want := range map[string]string{
		"8000, 8001":       "8000,8001",
		" 40001 , 40002 ":  "40001,40002",
		"8000-8010,\t9000": "8000:8010,9000",
		"":                 "",
	} {
		if got := iptablesPortSpec(value); got != want {
			t.Errorf("iptablesPortSpec(%q) = %q, want %q", value, got, want)
		}
	}
}

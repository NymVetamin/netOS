package firewall

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

func TestAnnotationConfirmationAndMixedChanges(t *testing.T) {
	base, _ := configuredFirewall(t)
	base.Firewall.Rules = []config.FirewallRule{{ID: "a", Name: "allow", Enabled: true, Zone: "lan", Flow: "forward", Action: "accept"}, {ID: "b", Name: "deny", Enabled: true, Zone: "lan", Flow: "forward", Action: "drop"}}
	base.Firewall.NAT = []config.NATRule{{ID: "nat", Name: "source", Enabled: true, Direction: "source", Interface: "eth0", Source: "192.0.2.0/24"}}
	for _, tc := range []struct {
		name   string
		change func(*config.Config)
		safe   bool
	}{
		{"rename rule", func(c *config.Config) { c.Firewall.Rules[0].Name = "new" }, true},
		{"logging", func(c *config.Config) { c.Firewall.Rules[0].Log = true }, true},
		{"rename nat", func(c *config.Config) { c.Firewall.NAT[0].Name = "new" }, true},
		{"verdict", func(c *config.Config) { c.Firewall.Rules[0].Action = "drop" }, false},
		{"selector", func(c *config.Config) { c.Firewall.Rules[0].DstIP = "198.51.100.1" }, false},
		{"order", func(c *config.Config) {
			c.Firewall.Rules[0], c.Firewall.Rules[1] = c.Firewall.Rules[1], c.Firewall.Rules[0]
		}, false},
		{"nat address", func(c *config.Config) { c.Firewall.NAT[0].ToSource = "198.51.100.1" }, false},
		{"mixed output", func(c *config.Config) { c.Firewall.Rules[0].Log = true; c.Firewall.OutputPolicy = "drop" }, false},
		{"mixed ipv6", func(c *config.Config) { c.Firewall.Rules[0].Name = "new"; c.IPv6.Mode = "passthrough" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, _ := json.Marshal(base)
			var next config.Config
			if err := json.Unmarshal(before, &next); err != nil {
				t.Fatal(err)
			}
			tc.change(&next)
			rules, err := Build(base)
			if err != nil {
				t.Fatal(err)
			}
			actions, err := New(cleanFirewallRunner(rules), t.TempDir()).Plan(base, &next)
			if err != nil {
				t.Fatal(err)
			}
			if len(actions) == 0 {
				t.Fatal("missing action")
			}
			for i := range actions {
				actions[i].Subsystem = "firewall"
			}
			if got := !apply.NeedsConfirmation(actions); got != tc.safe {
				t.Fatalf("safe=%v want=%v actions=%+v", got, tc.safe, actions)
			}
			after, _ := json.Marshal(base)
			if string(after) != string(before) {
				t.Fatal("plan mutated original revision")
			}
		})
	}
}

func TestAnnotationChangeDoesNotHideLiveRepair(t *testing.T) {
	for _, mode := range []string{"drift", "read failure", "ipv6 drift"} {
		t.Run(mode, func(t *testing.T) {
			base, _ := configuredFirewall(t)
			base.Firewall.Rules = []config.FirewallRule{{ID: "r", Name: "old", Enabled: true, Zone: "lan", Flow: "forward", Action: "accept"}}
			rules, err := Build(base)
			if err != nil {
				t.Fatal(err)
			}
			runner := cleanFirewallRunner(rules)
			switch mode {
			case "drift":
				runner.outputs["iptables-save"] = ""
			case "read failure":
				runner.runErrors["iptables-save"] = errors.New("unavailable")
			case "ipv6 drift":
				runner.outputs["ip6tables-save"] = ""
			}
			next := *base
			next.Firewall.Rules = append([]config.FirewallRule(nil), base.Firewall.Rules...)
			next.Firewall.Rules[0].Name = "new"
			actions, err := New(runner, t.TempDir()).Plan(base, &next)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range actions {
				if a.Confirmation == apply.ConfirmationSafe {
					t.Fatal("live repair classified safe")
				}
			}
		})
	}
}

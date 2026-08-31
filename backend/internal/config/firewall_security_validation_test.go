package config

import "testing"

func firewallValidationConfig() *Config {
	cfg := Default()
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, FirewallRule{
		ID: "qa-rule", Name: "QA", Enabled: true, Zone: "global", Flow: "in",
		Action: "accept", Protocol: "tcp", Interface: "eth0", ConnState: "new,established",
		Schedule: &Schedule{Days: []string{"Mon", "Fri"}, TimeStart: "08:30", TimeStop: "18:00:59"},
	})
	cfg.Policies = append(cfg.Policies, Policy{
		ID: "qa-policy", Name: "QA", Enabled: false, Priority: 100, Channel: "direct",
		SrcIP: "192.0.2.0/24", Schedule: &Schedule{Days: []string{"Tue"}, TimeStart: "09:00", TimeStop: "17:00"},
	})
	return cfg
}

func TestFirewallAndPolicySchedulesValidateSafeValues(t *testing.T) {
	cfg := firewallValidationConfig()
	for _, path := range []string{"firewall.rules", "policies"} {
		if problem(t, cfg, path, "время") || problem(t, cfg, path, "день") {
			t.Fatalf("valid schedule rejected at %s", path)
		}
	}
}

func TestFirewallValidationRejectsRulesetInjectionAndInvalidSelectors(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		mutate func(*Config)
	}{
		{"protocol", "firewall.rules", func(c *Config) { c.Firewall.Rules[len(c.Firewall.Rules)-1].Protocol = "tcp\n-A INPUT -j ACCEPT" }},
		{"interface", "firewall.rules", func(c *Config) { c.Firewall.Rules[len(c.Firewall.Rules)-1].Interface = "eth0\n-A" }},
		{"state", "firewall.rules", func(c *Config) { c.Firewall.Rules[len(c.Firewall.Rules)-1].ConnState = "new,evil" }},
		{"rule day", "firewall.rules", func(c *Config) {
			c.Firewall.Rules[len(c.Firewall.Rules)-1].Schedule.Days = []string{"Mon\n-A INPUT -j ACCEPT"}
		}},
		{"rule start", "firewall.rules", func(c *Config) {
			c.Firewall.Rules[len(c.Firewall.Rules)-1].Schedule.TimeStart = "00:00\n-A INPUT -j ACCEPT"
		}},
		{"rule stop", "firewall.rules", func(c *Config) { c.Firewall.Rules[len(c.Firewall.Rules)-1].Schedule.TimeStop = "24:00" }},
		{"policy day", "policies", func(c *Config) { c.Policies[len(c.Policies)-1].Schedule.Days = []string{"Monday"} }},
		{"policy time", "policies", func(c *Config) { c.Policies[len(c.Policies)-1].Schedule.TimeStart = "9:00" }},
		{"nat interface", "firewall.nat", func(c *Config) {
			c.Firewall.NAT = append(c.Firewall.NAT, NATRule{ID: "qa-nat", Enabled: true, Direction: "source", Interface: "eth0\n-A", Source: "192.0.2.0/24"})
		}},
		{"nat IPv6 source", "firewall.nat", func(c *Config) {
			c.Firewall.NAT = append(c.Firewall.NAT, NATRule{ID: "qa-nat", Enabled: true, Direction: "source", Interface: "eth0", Source: "2001:db8::/32"})
		}},
		{"nat IPv6 destination", "firewall.nat", func(c *Config) {
			c.Firewall.NAT = append(c.Firewall.NAT, NATRule{ID: "qa-nat", Enabled: true, Direction: "destination", Protocol: "tcp", ExtPort: "65000", DestIP: "2001:db8::1", DestPort: "65001"})
		}},
	}
	for _, tc := range tests {
		cfg := firewallValidationConfig()
		tc.mutate(cfg)
		if !problem(t, cfg, tc.path, "") {
			t.Fatalf("unsafe firewall value accepted (%s) at %s", tc.name, tc.path)
		}
	}
}

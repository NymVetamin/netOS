package firewall

import "github.com/netos-router/netos/internal/config"

// annotationsOnly compares generated rules after removing a narrow allowlist
// of display-only fields and per-rule logging. All packet selectors, verdicts,
// rule order, NAT and routing remain part of the comparison. Copies keep the
// revision and the actual rules applied to the OS untouched.
func annotationsOnly(old, next *config.Config) bool {
	before, err := Build(withoutRuleAnnotations(old))
	if err != nil {
		return false
	}
	after, err := Build(withoutRuleAnnotations(next))
	return err == nil && before.IPv4 == after.IPv4 && before.IPv6 == after.IPv6
}

func withoutRuleAnnotations(cfg *config.Config) *config.Config {
	copy := *cfg
	copy.VPNServers = append([]config.VPNServer(nil), cfg.VPNServers...)
	for i := range copy.VPNServers {
		copy.VPNServers[i].Name = "annotation"
	}
	copy.Channels = append([]config.Channel(nil), cfg.Channels...)
	for i := range copy.Channels {
		copy.Channels[i].Name = "annotation"
	}
	copy.Networks = append([]config.Network(nil), cfg.Networks...)
	for i := range copy.Networks {
		copy.Networks[i].Name = "annotation"
	}
	copy.Clients = append([]config.Client(nil), cfg.Clients...)
	for i := range copy.Clients {
		copy.Clients[i].Name = "annotation"
	}
	copy.Policies = append([]config.Policy(nil), cfg.Policies...)
	for i := range copy.Policies {
		copy.Policies[i].Name = "annotation"
		copy.Policies[i].Comment = ""
	}
	copy.Firewall.Rules = append([]config.FirewallRule(nil), cfg.Firewall.Rules...)
	for i := range copy.Firewall.Rules {
		copy.Firewall.Rules[i].Name = "annotation"
		copy.Firewall.Rules[i].Log = false
	}
	copy.Firewall.NAT = append([]config.NATRule(nil), cfg.Firewall.NAT...)
	for i := range copy.Firewall.NAT {
		copy.Firewall.NAT[i].Name = "annotation"
	}
	return &copy
}

package firewall

import (
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

// Restrictions precede ESTABLISHED and user ACCEPT rules. Returning for an
// internal destination preserves the ordinary firewall/isolation decision.
type internetRestrictions struct {
	mac []string
	vpn []string
}

func (r internetRestrictions) empty() bool { return len(r.mac) == 0 && len(r.vpn) == 0 }

func internetBlockMatches(cfg *config.Config, ipv6 bool) []string {
	rules := internetBlockRestrictions(cfg, ipv6)
	matches := append(rules.mac, rules.vpn...)
	sort.Strings(matches)
	return matches
}

func internetBlockRestrictions(cfg *config.Config, ipv6 bool) internetRestrictions {
	var rules internetRestrictions
	for _, c := range cfg.Clients {
		if !c.Blocked && c.Channel == config.InternetBlockChannel && c.MAC != "" {
			rules.mac = append(rules.mac, " -m mac --mac-source "+strings.ToLower(c.MAC))
		}
	}
	if !ipv6 {
		for _, s := range cfg.VPNServers {
			if !s.Enabled || s.Type == "xray" {
				continue
			}
			for _, p := range s.Peers {
				if !p.Enabled || p.Channel != config.InternetBlockChannel {
					continue
				}
				match := " -i " + vpnservers.MatchInterfaceName(s) + " -s " + p.Address + "/32"
				if s.Type == "ikev2" {
					match = " -s " + p.Address + "/32 -m policy --dir in --pol ipsec"
				}
				rules.vpn = append(rules.vpn, match)
			}
		}
	}
	sort.Strings(rules.mac)
	sort.Strings(rules.vpn)
	return rules
}

func (b *builder) internetBlockChecks(rules internetRestrictions, chain string, vpn bool) {
	emit := func(matches []string) {
		for _, match := range matches {
			b.line("-A %s%s -m comment --comment %q -j NETOS-INTERNET-BLOCK", chain, match, "запрет интернета клиенту")
		}
	}
	emit(rules.mac)
	if vpn {
		emit(rules.vpn)
	}
}

func (b *builder) internetBlockDestinations(cfg *config.Config, ipv6 bool) {
	b.line(":NETOS-INTERNET-BLOCK - [0:0]")
	destinations := map[string]bool{}
	if ipv6 {
		// Passthrough has no configured IPv6 prefixes: retain forwarding between
		// internal links, while denying WAN/exit links (including public IPv6).
		for _, n := range cfg.Networks {
			if n.Enabled {
				if name := cfg.InterfaceName(n.Interface); name != "" {
					destinations[" -o "+name] = true
				}
			}
		}
	} else {
		for _, segment := range cfg.InternalSegments() {
			destinations[" -d "+segment.Subnet] = true
		}
	}
	keys := make([]string, 0, len(destinations))
	for key := range destinations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b.line("-A NETOS-INTERNET-BLOCK%s -j RETURN", key)
	}
	b.line("-A NETOS-INTERNET-BLOCK -j DROP")
}

// Even with ordinary filtering disabled, the explicit internet-only restriction
// remains active. Dispatch once by zone; unclassified interfaces retain the same
// MAC restriction instead of becoming a bypass.
func (b *builder) openForwardRestrictions(cfg *config.Config, ipv6 bool) {
	rules := internetBlockRestrictions(cfg, ipv6)
	if rules.empty() {
		return
	}
	b.internetBlockDestinations(cfg, ipv6)
	zones := buildZoneMap(cfg)
	names := make([]string, 0, len(zones))
	for name := range zones {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		chain := ChainName(name, "FWD")
		b.line(":%s - [0:0]", chain)
		b.internetBlockChecks(rules, chain, name == "vpn")
		b.line("-A %s -j ACCEPT", chain)
	}
	if !ipv6 && ikev2ServerEnabled(cfg) && len(zones["vpn"]) > 0 {
		b.line("-A FORWARD -m policy --dir in --pol ipsec -j %s", ChainName("vpn", "FWD"))
	}
	for _, name := range names {
		for _, iface := range zones[name] {
			b.line("-A FORWARD -i %s -j %s", iface, ChainName(name, "FWD"))
		}
	}
	b.line(":NETOS-FWD-OTHER - [0:0]")
	b.internetBlockChecks(rules, "NETOS-FWD-OTHER", len(zones["vpn"]) == 0)
	b.line("-A FORWARD -j NETOS-FWD-OTHER")
}

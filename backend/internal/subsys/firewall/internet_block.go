package firewall

import (
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

// Reserved packet-only mark: distinct from channel/WAN IDs, Xray's
// 0x40000000 and the 0x80000000 local-reply connmark discriminator.
const internetBlockMark = "0x20000000"

// Classify every packet, not only NEW: changes affect existing connections.
// Never save the block mark in conntrack, so removing a block cannot leave a
// stale restriction. ACCEPT ends only this mangle hook, not filter processing.
func (b *builder) internetBlockClassification(cfg *config.Config, ipv6 bool) {
	matches := internetBlockMatches(cfg, ipv6)
	if len(matches) == 0 {
		return
	}
	for _, match := range matches {
		b.line("-A PREROUTING%s -j MARK --set-mark %s", match, internetBlockMark)
	}
	b.line("-A PREROUTING -m mark --mark %s -j CONNMARK --set-mark 0", internetBlockMark)
	b.line("-A PREROUTING -m mark --mark %s -j ACCEPT", internetBlockMark)
}

// Restrictions precede ESTABLISHED and user ACCEPT rules. Returning for an
// internal destination preserves the ordinary firewall/isolation decision.
func internetBlockMatches(cfg *config.Config, ipv6 bool) []string {
	var matches []string
	for _, c := range cfg.Clients {
		if !c.Blocked && c.Channel == config.InternetBlockChannel && c.MAC != "" {
			matches = append(matches, " -m mac --mac-source "+strings.ToLower(c.MAC))
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
				matches = append(matches, match)
			}
		}
	}
	sort.Strings(matches)
	return matches
}

func (b *builder) internetBlockedClients(cfg *config.Config, ipv6 bool) {
	matches := internetBlockMatches(cfg, ipv6)
	if len(matches) == 0 {
		return
	}
	b.line(":NETOS-INTERNET-BLOCK - [0:0]")
	b.line("-A FORWARD -m mark --mark %s -m comment --comment %q -j NETOS-INTERNET-BLOCK", internetBlockMark, "запрет интернета клиенту")
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

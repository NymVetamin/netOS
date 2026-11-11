package vpnservers

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"net/netip"
	"slices"
	"strings"
)

// Shared by pre-activation protection and the final firewall ruleset.
func WireGuardExitGuard(server config.VPNServer) (string, []string) {
	exit := false
	for _, p := range server.Peers {
		exit = exit || (p.Enabled && p.UseAsChannel)
	}
	if !server.Enabled || !config.IsWireGuardType(server.Type) || !exit {
		return "", nil
	}
	chain := fmt.Sprintf("NETOS-WGEXIT%d", server.Index)
	rules := []string{fmt.Sprintf("-A %s -m conntrack --ctdir REPLY --ctstate ESTABLISHED,RELATED -j RETURN", chain)}
	if prefixes := wireGuardExitPrefixes(server.Peers); prefixes != nil {
		for _, prefix := range prefixes {
			rules = append(rules, fmt.Sprintf("-A %s -s %s -j RETURN", chain, prefix))
		}
	} else {
		// Preserve the original restore error for invalid addresses; never omit
		// an invalid peer and silently activate a different allowlist.
		for _, p := range server.Peers {
			if p.Enabled {
				rules = append(rules, fmt.Sprintf("-A %s -s %s/32 -j RETURN", chain, p.Address))
			}
		}
	}
	return chain, append(rules, "-A "+chain+" -j DROP")
}

// Merge only complete sibling prefixes: disabled peers and gaps stay denied.
// Preparation is O(P log P); packet traversal uses C <= P address rules.
func wireGuardExitPrefixes(peers []config.VPNPeer) []netip.Prefix {
	addresses := make([]netip.Addr, 0, len(peers))
	for _, peer := range peers {
		if !peer.Enabled {
			continue
		}
		address, err := netip.ParseAddr(peer.Address)
		if err != nil || !address.Is4() {
			return nil
		}
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	addresses = slices.Compact(addresses)
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		prefix := netip.PrefixFrom(address, 32)
		for len(prefixes) > 0 && prefix.Bits() > 0 {
			last := prefixes[len(prefixes)-1]
			if last.Bits() != prefix.Bits() {
				break
			}
			parent := netip.PrefixFrom(prefix.Addr(), prefix.Bits()-1).Masked()
			if !parent.Contains(last.Addr()) {
				break
			}
			prefixes = prefixes[:len(prefixes)-1]
			prefix = parent
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func (s *Subsystem) protectWireGuardExit(ctx context.Context, server config.VPNServer) error {
	chain, rules := WireGuardExitGuard(server)
	if chain == "" {
		return nil
	}
	// --noflush preserves unrelated chains; declaring this user chain replaces
	// its contents atomically. Install protection before widening AllowedIPs.
	body := "*mangle\n:" + chain + " - [0:0]\n" + strings.Join(rules, "\n") + "\nCOMMIT\n"
	if _, err := s.Runner.RunInput(ctx, body, "iptables-restore", "--wait", "--noflush"); err != nil {
		return err
	}
	args := []string{"-w", "-t", "mangle", "-C", "PREROUTING", "-i", InterfaceName(server), "-j", chain}
	if _, err := s.Runner.Run(ctx, "iptables", args...); err == nil {
		return nil
	}
	args[3] = "-I"
	_, err := s.Runner.Run(ctx, "iptables", args...)
	return err
}

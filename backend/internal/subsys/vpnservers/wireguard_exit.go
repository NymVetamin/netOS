package vpnservers

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"strings"
)

// Shared by pre-activation protection and the final firewall ruleset.
func WireGuardExitGuard(server config.VPNServer) (string, []string) {
	exit := false
	for _, p := range server.Peers {
		exit = exit || (p.Enabled && p.UseAsChannel)
	}
	if !server.Enabled || server.Type != "wireguard" || !exit {
		return "", nil
	}
	chain := fmt.Sprintf("NETOS-WGEXIT%d", server.Index)
	rules := []string{fmt.Sprintf("-A %s -m conntrack --ctdir REPLY --ctstate ESTABLISHED,RELATED -j RETURN", chain)}
	for _, p := range server.Peers {
		if p.Enabled {
			rules = append(rules, fmt.Sprintf("-A %s -s %s/32 -j RETURN", chain, p.Address))
		}
	}
	return chain, append(rules, "-A "+chain+" -j DROP")
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

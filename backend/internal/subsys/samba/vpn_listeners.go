package samba

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
)

// VPN addresses can appear after boot or only when a peer connects. smbd
// resolves its listening addresses at start and does not bind newly created
// interfaces by itself. Repair only a selected, present VPN listener; the
// generated Samba configuration and firewall remain the access boundary.
func (s *Subsystem) ReconcileVPNListeners(ctx context.Context, cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg == nil || !cfg.Samba.Enabled || len(cfg.Samba.VPNs) == 0 ||
		system.FileChanged(filepath.Join(s.StateDir, "samba", "applied"), s.stamp(cfg)) {
		return nil
	}
	addresses, err := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show")
	if err != nil {
		return fmt.Errorf("Samba VPN addresses: %w", err)
	}
	wanted := map[string]bool{}
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type == "xray" || !selected(cfg.Samba.VPNs, server.ID) {
			continue
		}
		prefix, err := netip.ParsePrefix(server.Subnet)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		iface := vpnservers.MatchInterfaceName(server)
		for _, line := range strings.Split(addresses, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[2] != "inet" {
				continue
			}
			name := strings.TrimSuffix(fields[1], ":")
			match := name == iface || (strings.HasSuffix(iface, "+") && strings.HasPrefix(name, strings.TrimSuffix(iface, "+")))
			if address, parseErr := netip.ParsePrefix(fields[3]); match && parseErr == nil && address.Addr() == prefix.Addr() {
				wanted[netip.AddrPortFrom(prefix.Addr(), 445).String()] = true
			}
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	listeners, err := s.Runner.Run(ctx, "ss", "-H", "-lnt")
	if err != nil {
		return fmt.Errorf("Samba VPN listeners: %w", err)
	}
	for _, line := range strings.Split(listeners, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			delete(wanted, fields[3])
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	if time.Now().Before(s.nextVPNRepair) {
		return nil
	}
	if err := system.NewSystemd(s.Runner).Restart(ctx, "netos-samba.service"); err != nil {
		s.nextVPNRepair = time.Now().Add(15 * time.Second)
		return fmt.Errorf("восстановление Samba VPN listener: %w", err)
	}
	s.nextVPNRepair = time.Now().Add(15 * time.Second)
	return nil
}

type listenerLogger interface{ Warnf(string, ...any) }

func (s *Subsystem) Run(ctx context.Context, current func() *config.Config, logger listenerLogger) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var retryAfter time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Now().Before(retryAfter) {
				continue
			}
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := s.ReconcileVPNListeners(checkCtx, current())
			cancel()
			if err != nil {
				logger.Warnf("Samba: %v", err)
				retryAfter = time.Now().Add(15 * time.Second)
			}
		}
	}
}

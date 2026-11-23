package samba

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
	present, err := s.presentVPNAddresses(ctx, cfg)
	if err != nil {
		return err
	}
	listeners, err := s.Runner.Run(ctx, "ss", "-H", "-lnt")
	if err != nil {
		return fmt.Errorf("Samba VPN listeners: %w", err)
	}
	bound := map[string]bool{}
	for _, line := range strings.Split(listeners, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			bound[fields[3]] = true
		}
	}
	confPath := filepath.Join(s.StateDir, "samba.conf")
	previous, err := os.ReadFile(confPath)
	if err != nil {
		return err
	}
	// A listening TCP socket survives removal of its local PPP address.
	// Keep an already bound, still-selected L2TP listener across reconnects
	// instead of restarting smbd twice and interrupting unrelated clients.
	// Before the first connection there is no socket to retain. Revoking
	// the VPN selection is handled by Apply and its ownership stamp.
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type != "l2tp" || !selected(cfg.Samba.VPNs, server.ID) || present[server.ID] != "" {
			continue
		}
		prefix, parseErr := netip.ParsePrefix(server.Subnet)
		if parseErr != nil || !prefix.Addr().Is4() {
			continue
		}
		address := netip.AddrPortFrom(prefix.Addr(), 445).String()
		if !bound[address] {
			continue
		}
		for _, line := range strings.Split(string(previous), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "interfaces = ") {
				for _, field := range strings.Fields(line) {
					if field == server.Subnet {
						present[server.ID] = address
					}
				}
			}
		}
	}
	conf, err := render(cfg, s.StateDir, present)
	if err != nil {
		return err
	}
	changed := string(previous) != conf
	wanted := map[string]bool{}
	for _, address := range present {
		wanted[address] = true
	}
	for address := range bound {
		delete(wanted, address)
	}
	// A new PPP address set must be applied even if the previous restart
	// was recent. Keep the cooldown only for retries of unchanged bindings
	// so a slow-starting smbd is not restarted on every reconciliation tick.
	if !changed && (len(wanted) == 0 || time.Now().Before(s.nextVPNRepair)) {
		return nil
	}
	if changed {
		pending, err := os.CreateTemp(s.StateDir, ".samba-validate-*")
		if err != nil {
			return err
		}
		defer os.Remove(pending.Name())
		if _, err = pending.WriteString(conf); err != nil {
			_ = pending.Close()
			return err
		}
		if err = pending.Close(); err != nil {
			return err
		}
		if _, err = s.Runner.Run(ctx, "testparm", "--suppress-prompt", pending.Name()); err != nil {
			return fmt.Errorf("Samba VPN config: %w", err)
		}
		if _, err = s.write("samba.conf", []byte(conf), 0600); err != nil {
			return err
		}
	}
	if err := system.NewSystemd(s.Runner).Restart(ctx, "netos-samba.service"); err != nil {
		if changed {
			_, _ = s.write("samba.conf", previous, 0600)
			_ = system.NewSystemd(s.Runner).Restart(ctx, "netos-samba.service")
		}
		s.nextVPNRepair = time.Now().Add(15 * time.Second)
		return fmt.Errorf("восстановление Samba VPN listener: %w", err)
	}
	s.nextVPNRepair = time.Now().Add(15 * time.Second)
	return nil
}

func (s *Subsystem) renderActive(ctx context.Context, cfg *config.Config) (string, error) {
	for _, server := range cfg.VPNServers {
		if server.Enabled && server.Type == "l2tp" && selected(cfg.Samba.VPNs, server.ID) {
			present, err := s.presentVPNAddresses(ctx, cfg)
			if err != nil {
				return "", err
			}
			return render(cfg, s.StateDir, present)
		}
	}
	return Render(cfg, s.StateDir)
}

func (s *Subsystem) presentVPNAddresses(ctx context.Context, cfg *config.Config) (map[string]string, error) {
	addresses, err := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("Samba VPN addresses: %w", err)
	}
	selectedIDs := make(map[string]bool, len(cfg.Samba.VPNs))
	for _, id := range cfg.Samba.VPNs {
		selectedIDs[id] = true
	}
	present := map[string]string{}
	var byAddress map[netip.Addr][]string
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type == "xray" || !selectedIDs[server.ID] {
			continue
		}
		prefix, err := netip.ParsePrefix(server.Subnet)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		if byAddress == nil {
			byAddress = ipv4InterfacesByAddress(addresses)
		}
		names := byAddress[prefix.Addr()]
		base, wildcard := strings.CutSuffix(vpnservers.MatchInterfaceName(server), "+")
		i, exact := slices.BinarySearch(names, base)
		if exact || (wildcard && i < len(names) && strings.HasPrefix(names[i], base)) {
			present[server.ID] = netip.AddrPortFrom(prefix.Addr(), 445).String()
		}
	}
	return present, nil
}

func ipv4InterfacesByAddress(addresses string) map[netip.Addr][]string {
	byAddress := make(map[netip.Addr][]string)
	for line := range strings.SplitSeq(addresses, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "inet" {
			continue
		}
		var addr netip.Addr
		if strings.Contains(fields[3], "/") {
			prefix, _ := netip.ParsePrefix(fields[3])
			addr = prefix.Addr()
		} else {
			addr, _ = netip.ParseAddr(fields[3])
		}
		if addr.Is4() {
			byAddress[addr] = append(byAddress[addr], strings.TrimSuffix(fields[1], ":"))
		}
	}
	for _, names := range byAddress {
		slices.Sort(names)
	}
	return byAddress
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

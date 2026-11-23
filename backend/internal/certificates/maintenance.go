package certificates

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// HTTPBootstrap admits only ACME HTTP-01 during initial issuance. The canonical
// firewall later retains port 80 iff at least one configured service uses ACME.
func HTTPBootstrap(runner system.Runner) func(context.Context) (func(), error) {
	return func(ctx context.Context) (func(), error) {
		var added []string
		rule := []string{"INPUT", "-p", "tcp", "--dport", "80", "-m", "comment", "--comment", "netOS ACME bootstrap", "-j", "ACCEPT"}
		cleanup := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, tool := range added {
				_, _ = runner.Run(ctx, tool, append([]string{"-w", "5", "-D"}, rule...)...)
			}
		}
		for _, tool := range []string{"iptables", "ip6tables"} {
			if _, err := runner.Run(ctx, tool, append([]string{"-w", "5", "-C"}, rule...)...); err == nil {
				continue
			}
			if _, err := runner.Run(ctx, tool, append([]string{"-w", "5", "-I"}, rule...)...); err != nil {
				cleanup()
				return nil, fmt.Errorf("доступ HTTP-01: %w", err)
			}
			added = append(added, tool)
		}
		return cleanup, nil
	}
}

// Refresh is called while the apply engine holds its operation lock, so a
// stale background configuration cannot overwrite newly-applied credentials.
func (m *Manager) Refresh(ctx context.Context, cfg *config.Config, generated string, runner system.Runner) error {
	if cfg == nil {
		return nil
	}
	var first error
	active := make(map[string]bool)
	vpnIDs := make(map[string]bool, len(cfg.VPNServers))
	if spec := cfg.System.Panel.TLS; spec.Mode == "acme" {
		active[hostname(spec.Domain)] = true
	}
	if _, err := m.Panel(ctx, cfg); err != nil {
		first = err
	}
	for _, server := range cfg.VPNServers {
		vpnIDs[server.ID] = true
		if !server.Enabled {
			continue
		}
		spec, endpoint, err := server.ServerTLS()
		if err != nil || !spec.Managed() {
			continue
		}
		if spec.Mode == "acme" {
			active[hostname(spec.Domain)] = true
		}
		dir := filepath.Join(generated, fmt.Sprintf("%s-srv%d-tls", server.Type, server.Index))
		err = m.refreshVPN(ctx, cfg, server, dir, spec, endpoint, runner)
		if err != nil && first == nil {
			first = err
		}
	}
	m.removeUnused(active, vpnIDs)
	return first
}

func (m *Manager) removeUnused(active, vpnIDs map[string]bool) {
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	for name := range m.status {
		if id, vpn := strings.CutPrefix(name, "vpn:"); vpn && !vpnIDs[id] {
			delete(m.status, name)
		}
	}
	var retired []ACME
	for domain, issuer := range m.issuers {
		if !active[domain] {
			delete(m.issuers, domain)
			retired = append(retired, issuer.client)
		}
	}
	m.mu.Unlock()
	for _, client := range retired {
		client.Close()
	}
}

func (m *Manager) refreshVPN(ctx context.Context, cfg *config.Config, server config.VPNServer, dir string, spec *config.VPNServerTLS, endpoint string, runner system.Runner) error {
	m.op.Lock()
	defer m.op.Unlock()
	var marker string
	if server.Type == "ocserv" {
		marker = filepath.Join(dir, "reload-pending")
	}
	changed, err := m.vpnLocked(ctx, cfg, server, dir, spec, endpoint, marker)
	if err != nil || marker == "" {
		return err
	}
	if !changed {
		if _, err := os.Lstat(marker); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
	}
	if _, err := runner.Run(ctx, "systemctl", "kill", "--kill-whom=main", "--signal=HUP", fmt.Sprintf("netos-ocserv-srv%d.service", server.Index)); err != nil {
		return err
	}
	return os.Remove(marker)
}

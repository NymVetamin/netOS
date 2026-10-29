package certificates

import (
	"context"
	"fmt"
	"path/filepath"
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
	if _, err := m.Panel(ctx, cfg); err != nil {
		first = err
	}
	for _, server := range cfg.VPNServers {
		if !server.Enabled {
			continue
		}
		spec, _, err := server.ServerTLS()
		if err != nil || !spec.Managed() {
			continue
		}
		dir := filepath.Join(generated, fmt.Sprintf("%s-srv%d-tls", server.Type, server.Index))
		changed, err := m.VPN(ctx, cfg, server, dir)
		// Xray hot-reloads these files hourly without interrupting sessions.
		if err == nil && changed && server.Type == "ocserv" {
			_, err = runner.Run(ctx, "systemctl", "kill", "--kill-whom=main", "--signal=HUP", fmt.Sprintf("netos-ocserv-srv%d.service", server.Index))
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

package services

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/netos-router/netos/internal/config"
)

// RecoverStartup restores an already configured resolver before components
// need DNS to download missing binaries. It never installs packages, fetches
// blocklists, switches providers or changes resolv.conf. In particular, a new
// installation still uses its system resolver until normal DNS Apply succeeds.
func (s *DNS) RecoverStartup(ctx context.Context, cfg *config.Config) error {
	m := s.M
	if !m.Resolv.Needed(cfg) || m.Resolv.changed([]byte(m.Resolv.Render(cfg))) {
		return nil
	}
	type provider struct{ unit, path, content, unitContent string }
	var providers []provider
	switch cfg.DNS.Provider {
	case "dnsmasq":
		providers = append(providers, provider{dnsmasqUnit, dnsmasqConfPath, m.Dnsmasq.Render(cfg), dnsmasqUnitContent()})
	case "unbound":
		providers = append(providers, provider{unboundUnit, unboundConfPath, m.Unbound.Render(cfg), unboundUnitContent()})
	case "dnsproxy":
		providers = append(providers, provider{dnsproxyUnit, dnsproxyConfPath, m.Dnsproxy.Render(cfg), dnsproxyUnitContent()})
	default:
		return fmt.Errorf("неизвестный DNS-провайдер %q", cfg.DNS.Provider)
	}
	if cfg.DNS.Provider != "dnsmasq" && (dnsFrontendNeeded(cfg) || localDNSNeeded(cfg)) {
		providers = append(providers, provider{dnsmasqUnit, dnsmasqConfPath, m.Dnsmasq.Render(cfg), dnsmasqUnitContent()})
	}
	// Validate the entire saved chain before starting any service. A stale or
	// foreign file must not silently become the router's resolver during boot.
	for _, p := range providers {
		if err := managedFileHealth(p.path, []byte(p.content), 0o644); err != nil {
			return err
		}
		if err := managedFileHealth(filepath.Join(systemdUnitDir, p.unit), []byte(p.unitContent), 0o644); err != nil {
			return err
		}
	}
	for _, p := range providers {
		if err := m.Systemd.Start(ctx, p.unit); err != nil {
			return fmt.Errorf("ранний запуск DNS %s: %w", p.unit, err)
		}
	}
	return nil
}

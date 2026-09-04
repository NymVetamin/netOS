package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Manager сводит вместе провайдеров DHCP и DNS. Демоны у ролей могут
// совпадать (dnsmasq умеет обе), поэтому владение процессами держим в одном
// месте, а подсистемы dhcp и dns лишь дёргают его.
type Manager struct {
	Dnsmasq   *Dnsmasq
	ISC       *ISCDHCP
	Kea       *KeaDHCP
	Unbound   *Unbound
	Dnsproxy  *Dnsproxy
	Resolv    *SystemResolver
	Blocklist *BlocklistManager
	Packages  *system.Packages
	Systemd   *system.Systemd
}

func NewManager(r system.Runner) *Manager {
	return &Manager{
		Dnsmasq:   NewDnsmasq(r),
		ISC:       NewISCDHCP(r),
		Kea:       NewKeaDHCP(r),
		Unbound:   NewUnbound(r),
		Dnsproxy:  NewDnsproxy(r),
		Resolv:    NewSystemResolver(r),
		Blocklist: NewBlocklistManager(),
		Packages:  system.NewPackages(r),
		Systemd:   system.NewSystemd(r),
	}
}

// ensurePackages доустанавливает демон, который выбрал пользователь. Базовая
// установка netOS тянет только dnsmasq, остальное подтягивается по факту
// выбора в панели.
func (m *Manager) ensurePackages(ctx context.Context, cfg *config.Config) error {
	need := map[string]bool{}
	if hasKernelDomainPolicies(cfg) {
		need["dnsmasq"] = true
		need["ipset"] = true
	}
	if cfg.DHCP.Enabled {
		switch cfg.DHCP.Provider {
		case "dnsmasq":
			need["dnsmasq"] = true
		case "isc-dhcp-server":
			need["isc-dhcp-server"] = true
		case "kea":
			need["kea-dhcp4-server"] = true
		}
	}
	if cfg.DNS.Enabled {
		switch cfg.DNS.Provider {
		case "dnsmasq":
			need["dnsmasq"] = true
		case "unbound":
			need["unbound"] = true
			if cfg.DNS.DNSSEC {
				// Якорь доверия создаёт unbound-anchor, а он в Debian
				// поставляется отдельным пакетом.
				need["unbound-anchor"] = true
			}
			// Локальную зону обслуживает dnsmasq, поэтому он нужен и тогда,
			// когда сам резолвером не работает.
			if cfg.DHCP.Enabled && cfg.DHCP.Provider == "dnsmasq" {
				need["dnsmasq"] = true
			}
		case "dnsproxy":
			// Сам dnsproxy ставится не из apt, а подсистемой компонентов.
			// Здесь нужен только dnsmasq — ради локальной зоны.
			if cfg.DHCP.Enabled && cfg.DHCP.Provider == "dnsmasq" {
				need["dnsmasq"] = true
			}
		}
	}
	if len(need) == 0 {
		return nil
	}
	pkgs := make([]string, 0, len(need))
	for p := range need {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	_, err := m.Packages.Ensure(ctx, pkgs...)
	return err
}

func (m *Manager) preflightDHCP(ctx context.Context, cfg *config.Config) error {
	if !cfg.DHCP.Enabled {
		return nil
	}
	switch cfg.DHCP.Provider {
	case "dnsmasq":
		content := []byte(m.Dnsmasq.Render(cfg))
		return validateManagedContent(dnsmasqConfPath, content, 0o644, func(path string) error {
			if _, err := m.Dnsmasq.Runner.Run(ctx, "dnsmasq", "--test", "--conf-file="+path); err != nil {
				return fmt.Errorf("проверка конфигурации dnsmasq: %w", err)
			}
			return nil
		})
	case "isc-dhcp-server":
		if len(m.ISC.interfaces(cfg)) == 0 {
			return fmt.Errorf("ISC DHCP: нет включённых пулов на доступных интерфейсах")
		}
		content := []byte(m.ISC.Render(cfg))
		return validateManagedContent(iscConfPath, content, 0o644, func(path string) error {
			lease, err := os.CreateTemp(filepath.Dir(path), ".netos-dhcpd-leases-*")
			if err != nil {
				return err
			}
			leasePath := lease.Name()
			_ = lease.Close()
			defer os.Remove(leasePath)
			if _, err := m.ISC.Runner.Run(ctx, "dhcpd", "-4", "-t", "-cf", path, "-lf", leasePath); err != nil {
				return fmt.Errorf("проверка конфигурации ISC DHCP: %w", err)
			}
			return nil
		})
	case "kea":
		content := []byte(m.Kea.Render(cfg))
		return validateManagedContent(keaConfPath, content, 0o644, func(path string) error {
			if _, err := m.Kea.Runner.Run(ctx, "kea-dhcp4", "-t", path); err != nil {
				return fmt.Errorf("проверка конфигурации Kea DHCP: %w", err)
			}
			return nil
		})
	}
	return nil
}

func (m *Manager) preflightDNS(ctx context.Context, cfg *config.Config) error {
	if !cfg.DNS.Enabled {
		return nil
	}
	switch cfg.DNS.Provider {
	case "dnsmasq":
		return m.preflightDnsmasq(ctx, cfg)
	case "unbound":
		if cfg.DNS.DNSSEC {
			if err := m.Unbound.ensureTrustAnchor(ctx); err != nil {
				return err
			}
		}
		content := []byte(m.Unbound.Render(cfg))
		if err := validateManagedContent(unboundConfPath, content, 0o644, func(path string) error {
			if _, err := m.Unbound.Runner.Run(ctx, "unbound-checkconf", path); err != nil {
				return fmt.Errorf("проверка конфигурации unbound: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	case "dnsproxy":
		if _, err := os.Stat(dnsproxyBinary); err != nil {
			return fmt.Errorf("dnsproxy выбран резолвером, но не установлен")
		}
	}
	if hasKernelDomainPolicies(cfg) && cfg.DNS.Provider != "dnsmasq" {
		return m.preflightDnsmasq(ctx, cfg)
	}
	return nil
}

func (m *Manager) preflightDnsmasq(ctx context.Context, cfg *config.Config) error {
	content := []byte(m.Dnsmasq.Render(cfg))
	return validateManagedContent(dnsmasqConfPath, content, 0o644, func(path string) error {
		if _, err := m.Dnsmasq.Runner.Run(ctx, "dnsmasq", "--test", "--conf-file="+path); err != nil {
			return fmt.Errorf("проверка конфигурации dnsmasq: %w", err)
		}
		return nil
	})
}

// stopUnused гасит демонов, которые перестали быть выбранными провайдерами.
// Без этого старый демон продолжит держать порт 53 или отвечать на DHCP.
func (m *Manager) stopUnused(ctx context.Context, cfg *config.Config) error {
	var failures []string
	disable := func(unit string) {
		if err := m.Systemd.Disable(ctx, unit); err != nil {
			failures = append(failures, unit+": "+err.Error())
		}
	}
	// Пакетные юниты всегда чужие: netOS запускает демоны только собственными
	// юнитами с конфигами из /var/lib/netos/generated.
	disable("isc-dhcp-server.service")
	disable("kea-dhcp4-server.service")
	if !cfg.DHCP.Enabled || cfg.DHCP.Provider != "isc-dhcp-server" {
		disable(iscUnit)
	}
	if !cfg.DHCP.Enabled || cfg.DHCP.Provider != "kea" {
		disable(keaUnit)
	}
	// Штатные юниты dnsmasq и unbound всегда выключены: netOS запускает свои,
	// с генерируемыми конфигами. Собственный юнет резолвера гасит его же
	// подсистема, когда провайдер сменился.
	disable("dnsmasq.service")
	disable("unbound.service")
	if len(failures) > 0 {
		return fmt.Errorf("не удалось остановить неиспользуемые службы: %s", strings.Join(failures, "; "))
	}
	if !cfg.DHCP.Enabled || cfg.DHCP.Provider != "isc-dhcp-server" {
		if err := removeGenerated(iscConfPath); err != nil {
			return err
		}
	}
	if !cfg.DHCP.Enabled || cfg.DHCP.Provider != "kea" {
		if err := removeGenerated(keaConfPath); err != nil {
			return err
		}
	}
	return nil
}

func removeGenerated(paths ...string) error {
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("удаление неиспользуемого конфига %s: %w", path, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------

// DHCP — подсистема выдачи адресов.
type DHCP struct{ M *Manager }

func NewDHCP(m *Manager) *DHCP { return &DHCP{M: m} }

func (s *DHCP) Name() string { return "dhcp" }

func (s *DHCP) Plan(old, new *config.Config) ([]apply.Action, error) {
	return s.PlanContext(context.Background(), old, new)
}

func (s *DHCP) PlanContext(ctx context.Context, old, new *config.Config) ([]apply.Action, error) {
	if !new.DHCP.Enabled {
		if old != nil && old.DHCP.Enabled {
			return []apply.Action{{Kind: "delete", Target: "DHCP-сервер", Disruptive: true}}, nil
		}
		if err := s.Health(ctx, new); err != nil {
			return []apply.Action{{Kind: "repair", Target: "DHCP-сервер", Detail: err.Error()}}, nil
		}
		return nil, nil
	}
	if old == nil || !old.DHCP.Enabled {
		return []apply.Action{{
			Kind: "create", Target: "DHCP-сервер", Detail: new.DHCP.Provider,
		}}, nil
	}
	if old.DHCP.Provider != new.DHCP.Provider {
		return []apply.Action{{
			Kind:       "update",
			Target:     "DHCP-сервер",
			Detail:     fmt.Sprintf("%s → %s", old.DHCP.Provider, new.DHCP.Provider),
			Disruptive: true,
		}}, nil
	}

	// Провайдер тот же — сравниваем то, что реально попадёт в конфиг.
	sameRender := true
	switch new.DHCP.Provider {
	case "dnsmasq":
		sameRender = s.M.Dnsmasq.Render(old) == s.M.Dnsmasq.Render(new)
	case "isc-dhcp-server":
		sameRender = s.M.ISC.Render(old) == s.M.ISC.Render(new)
	case "kea":
		sameRender = s.M.Kea.Render(old) == s.M.Kea.Render(new)
	}
	if !sameRender {
		return []apply.Action{{Kind: "reload", Target: "DHCP-сервер", Detail: "конфигурация обновлена"}}, nil
	}
	if err := s.Health(ctx, new); err != nil {
		return []apply.Action{{Kind: "repair", Target: "DHCP-сервер", Detail: err.Error()}}, nil
	}
	return nil, nil
}

func (s *DHCP) Apply(ctx context.Context, cfg *config.Config) error {
	if err := s.M.ensurePackages(ctx, cfg); err != nil {
		return err
	}
	if err := s.M.preflightDHCP(ctx, cfg); err != nil {
		return err
	}
	if err := s.M.stopUnused(ctx, cfg); err != nil {
		return err
	}
	if cfg.DHCP.Provider != "dnsmasq" {
		// При переключении dnsmasq сначала убираем из него DHCP-роль (оставляя
		// DNS, если он выбран резолвером), и только затем запускаем новый сервер.
		if err := s.M.Dnsmasq.Apply(ctx, cfg); err != nil {
			return err
		}
	}

	switch cfg.DHCP.Provider {
	case "isc-dhcp-server":
		return s.M.ISC.Apply(ctx, cfg)
	case "kea":
		return s.M.Kea.Apply(ctx, cfg)
	}
	// Во всех остальных случаях решение принимает сам dnsmasq: он знает, нужен
	// ли хотя бы одной из ролей, и гасит собственный юнит, когда не нужен. Без
	// этого связка «DHCP выключен, резолвер unbound» оставила бы старый dnsmasq
	// работать и драться за порт 53.
	return s.M.Dnsmasq.Apply(ctx, cfg)
}

func (s *DHCP) Health(ctx context.Context, cfg *config.Config) error {
	for _, check := range []func(context.Context, *config.Config) error{
		s.M.Dnsmasq.Health, s.M.ISC.Health, s.M.Kea.Health,
	} {
		if err := check(ctx, cfg); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------

// DNS — подсистема резолвера.
type DNS struct{ M *Manager }

func NewDNS(m *Manager) *DNS { return &DNS{M: m} }

func (s *DNS) Name() string { return "dns" }

func (s *DNS) Plan(old, new *config.Config) ([]apply.Action, error) {
	return s.PlanContext(context.Background(), old, new)
}

func (s *DNS) PlanContext(ctx context.Context, old, new *config.Config) ([]apply.Action, error) {
	return append(s.planProvider(ctx, old, new), s.planSystemResolver(ctx, old, new)...), nil
}

func (s *DNS) planProvider(ctx context.Context, old, new *config.Config) []apply.Action {
	if !new.DNS.Enabled {
		if old != nil && old.DNS.Enabled {
			return []apply.Action{{Kind: "delete", Target: "DNS-резолвер", Disruptive: true}}
		}
		if err := s.providerHealth(ctx, new); err != nil {
			return []apply.Action{{Kind: "repair", Target: "DNS-резолвер", Detail: err.Error()}}
		}
		return nil
	}
	if old == nil || !old.DNS.Enabled {
		return []apply.Action{{Kind: "create", Target: "DNS-резолвер", Detail: new.DNS.Provider}}
	}
	if old.DNS.Provider != new.DNS.Provider {
		return []apply.Action{{
			Kind:       "update",
			Target:     "DNS-резолвер",
			Detail:     fmt.Sprintf("%s → %s", old.DNS.Provider, new.DNS.Provider),
			Disruptive: true,
		}}
	}
	if !slices.Equal(old.DNS.Blocklists, new.DNS.Blocklists) {
		return []apply.Action{{Kind: "reload", Target: "DNS blocklists", Detail: "источники или состояние списков изменены"}}
	}
	switch new.DNS.Provider {
	case "dnsmasq":
		if s.M.Dnsmasq.Render(old) != s.M.Dnsmasq.Render(new) {
			return []apply.Action{{Kind: "reload", Target: "DNS-резолвер", Detail: "конфигурация обновлена"}}
		}
	case "unbound":
		if s.M.Unbound.Render(old) != s.M.Unbound.Render(new) {
			return []apply.Action{{Kind: "reload", Target: "DNS-резолвер", Detail: "конфигурация обновлена"}}
		}
	case "dnsproxy":
		if s.M.Dnsproxy.Render(old) != s.M.Dnsproxy.Render(new) {
			return []apply.Action{{Kind: "reload", Target: "DNS-резолвер", Detail: "конфигурация обновлена"}}
		}
	}
	if err := s.M.Blocklist.Health(new); err != nil {
		return []apply.Action{{Kind: "repair", Target: "DNS blocklists", Detail: err.Error()}}
	}
	if err := s.providerHealth(ctx, new); err != nil {
		return []apply.Action{{Kind: "repair", Target: "DNS-резолвер", Detail: err.Error()}}
	}
	return nil
}

// planSystemResolver показывает смену резолвера самого роутера: это остановка
// systemd-resolved и подмена /etc/resolv.conf, то есть изменение, о котором
// администратор обязан узнать до применения, а не после.
func (s *DNS) planSystemResolver(ctx context.Context, old, new *config.Config) []apply.Action {
	was := old != nil && s.M.Resolv.Needed(old)
	will := s.M.Resolv.Needed(new)
	if was == will {
		if old != nil {
			if err := s.M.Resolv.Health(ctx, new); err != nil {
				return []apply.Action{{Kind: "repair", Target: "резолвер роутера", Detail: err.Error()}}
			}
		}
		return nil
	}
	if will {
		return []apply.Action{{
			Kind:   "update",
			Target: "резолвер роутера",
			Detail: "имена машины разрешает " + new.DNS.Provider + ", systemd-resolved останавливается",
		}}
	}
	return []apply.Action{{
		Kind:   "update",
		Target: "резолвер роутера",
		Detail: "возвращается системе",
	}}
}

// Apply для DNS почти всегда ничего не делает: если резолвер — dnsmasq, его
// уже применила подсистема dhcp, а повторный вызов идемпотентен и просто
// увидит, что файл не изменился.
func (s *DNS) Apply(ctx context.Context, cfg *config.Config) (retErr error) {
	if err := s.M.ensurePackages(ctx, cfg); err != nil {
		return err
	}
	blockChanged, blockTx, err := s.M.Blocklist.Apply(ctx, cfg)
	if err != nil {
		return err
	}
	serviceTx, err := snapshotDNSDomainTransition(ctx, s.M, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if retErr == nil {
			return
		}
		if rollbackErr := blockTx.Rollback(); rollbackErr != nil {
			retErr = fmt.Errorf("%w; возврат DNS blocklist также не удался: %v", retErr, rollbackErr)
		}
		if rollbackErr := serviceTx.Rollback(); rollbackErr != nil {
			retErr = fmt.Errorf("%w; возврат DNS frontend/backend также не удался: %v", retErr, rollbackErr)
		}
	}()
	if err := s.M.preflightDNS(ctx, cfg); err != nil {
		return err
	}
	if serviceTx != nil {
		serviceTx.armed = true
	}
	if !s.M.Dnsmasq.Needed(cfg) {
		if err := s.M.Dnsmasq.Apply(ctx, cfg); err != nil {
			return err
		}
	}
	// Резолвер, переставший быть выбранным, надо погасить прежде всего: иначе
	// он продолжит держать порт 53 и новый не поднимется. Apply провайдера сам
	// выключает свой юнит, когда провайдер не нужен.
	if !s.M.Unbound.Needed(cfg) {
		if err := s.M.Unbound.Apply(ctx, cfg); err != nil {
			return err
		}
	}
	if !s.M.Dnsproxy.Needed(cfg) {
		if err := s.M.Dnsproxy.Apply(ctx, cfg); err != nil {
			return err
		}
	}
	if !cfg.DNS.Enabled {
		// Резолвера у машины больше нет — значит и файл, которым netOS владел,
		// пора вернуть системе, иначе роутер остался бы без имён вовсе.
		return s.M.Resolv.Apply(ctx, cfg)
	}
	switch cfg.DNS.Provider {
	case "dnsmasq":
		if err := s.M.Dnsmasq.ApplyPrepared(ctx, cfg, blockChanged); err != nil {
			return err
		}
	case "unbound":
		if err := s.M.Unbound.ApplyPrepared(ctx, cfg, blockChanged); err != nil {
			return err
		}
	case "dnsproxy":
		if err := s.M.Dnsproxy.ApplyPrepared(ctx, cfg, blockChanged); err != nil {
			return err
		}
	}
	if cfg.DNS.Provider != "dnsmasq" && s.M.Dnsmasq.Needed(cfg) {
		if err := s.M.Dnsmasq.Apply(ctx, cfg); err != nil {
			return err
		}
	}
	// Резолвер роутера переключается последним — после того, как выбранный
	// демон уже поднят и проверен. Обратный порядок оставил бы машину без имён
	// на всё время применения, а с ней и apt, и проверки живости каналов.
	return s.M.Resolv.Apply(ctx, cfg)
}

func (s *DNS) Health(ctx context.Context, cfg *config.Config) error {
	if err := s.M.Blocklist.Health(cfg); err != nil {
		return err
	}
	if err := s.providerHealth(ctx, cfg); err != nil {
		return err
	}
	return s.M.Resolv.Health(ctx, cfg)
}

func (s *DNS) providerHealth(ctx context.Context, cfg *config.Config) error {
	for _, check := range []func(context.Context, *config.Config) error{
		s.M.Dnsmasq.Health, s.M.Unbound.Health, s.M.Dnsproxy.Health,
	} {
		if err := check(ctx, cfg); err != nil {
			return err
		}
	}
	return nil
}

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Manager сводит вместе провайдеров DHCP и DNS. Демоны у ролей могут
// совпадать (dnsmasq умеет обе), поэтому владение процессами держим в одном
// месте, а подсистемы dhcp и dns лишь дёргают его.
type Manager struct {
	Dnsmasq  *Dnsmasq
	ISC      *ISCDHCP
	Kea      *KeaDHCP
	Unbound  *Unbound
	Dnsproxy *Dnsproxy
	Resolv   *SystemResolver
	Packages *system.Packages
	Systemd  *system.Systemd
}

func NewManager(r system.Runner) *Manager {
	return &Manager{
		Dnsmasq:  NewDnsmasq(r),
		ISC:      NewISCDHCP(r),
		Kea:      NewKeaDHCP(r),
		Unbound:  NewUnbound(r),
		Dnsproxy: NewDnsproxy(r),
		Resolv:   NewSystemResolver(r),
		Packages: system.NewPackages(r),
		Systemd:  system.NewSystemd(r),
	}
}

// ensurePackages доустанавливает демон, который выбрал пользователь. Базовая
// установка netOS тянет только dnsmasq, остальное подтягивается по факту
// выбора в панели.
func (m *Manager) ensurePackages(ctx context.Context, cfg *config.Config) error {
	need := map[string]bool{}
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
	_, err := m.Packages.Ensure(ctx, pkgs...)
	return err
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
	return nil
}

// ---------------------------------------------------------------------------

// DHCP — подсистема выдачи адресов.
type DHCP struct{ M *Manager }

func NewDHCP(m *Manager) *DHCP { return &DHCP{M: m} }

func (s *DHCP) Name() string { return "dhcp" }

func (s *DHCP) Plan(old, new *config.Config) ([]apply.Action, error) {
	if !new.DHCP.Enabled {
		if old != nil && old.DHCP.Enabled {
			return []apply.Action{{Kind: "delete", Target: "DHCP-сервер", Disruptive: true}}, nil
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
	return nil, nil
}

func (s *DHCP) Apply(ctx context.Context, cfg *config.Config) error {
	if err := s.M.ensurePackages(ctx, cfg); err != nil {
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
	if !cfg.DHCP.Enabled {
		return nil
	}
	if cfg.DHCP.Provider == "dnsmasq" {
		return s.M.Dnsmasq.Health(ctx, cfg)
	}
	if cfg.DHCP.Provider == "isc-dhcp-server" {
		return s.M.ISC.Health(ctx, cfg)
	}
	if cfg.DHCP.Provider == "kea" {
		return s.M.Kea.Health(ctx, cfg)
	}
	return nil
}

// ---------------------------------------------------------------------------

// DNS — подсистема резолвера.
type DNS struct{ M *Manager }

func NewDNS(m *Manager) *DNS { return &DNS{M: m} }

func (s *DNS) Name() string { return "dns" }

func (s *DNS) Plan(old, new *config.Config) ([]apply.Action, error) {
	return append(s.planProvider(old, new), s.planSystemResolver(old, new)...), nil
}

func (s *DNS) planProvider(old, new *config.Config) []apply.Action {
	if !new.DNS.Enabled {
		if old != nil && old.DNS.Enabled {
			return []apply.Action{{Kind: "delete", Target: "DNS-резолвер", Disruptive: true}}
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
	return nil
}

// planSystemResolver показывает смену резолвера самого роутера: это остановка
// systemd-resolved и подмена /etc/resolv.conf, то есть изменение, о котором
// администратор обязан узнать до применения, а не после.
func (s *DNS) planSystemResolver(old, new *config.Config) []apply.Action {
	was := old != nil && s.M.Resolv.Needed(old)
	will := s.M.Resolv.Needed(new)
	if was == will {
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
func (s *DNS) Apply(ctx context.Context, cfg *config.Config) error {
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
		if err := s.M.Dnsmasq.Apply(ctx, cfg); err != nil {
			return err
		}
	case "unbound":
		if err := s.M.Unbound.Apply(ctx, cfg); err != nil {
			return err
		}
	case "dnsproxy":
		if err := s.M.Dnsproxy.Apply(ctx, cfg); err != nil {
			return err
		}
	}
	// Резолвер роутера переключается последним — после того, как выбранный
	// демон уже поднят и проверен. Обратный порядок оставил бы машину без имён
	// на всё время применения, а с ней и apt, и проверки живости каналов.
	return s.M.Resolv.Apply(ctx, cfg)
}

func (s *DNS) Health(ctx context.Context, cfg *config.Config) error {
	if !cfg.DNS.Enabled {
		return nil
	}
	if cfg.DNS.Provider == "dnsmasq" {
		return s.M.Dnsmasq.Health(ctx, cfg)
	}
	if cfg.DNS.Provider == "unbound" {
		return s.M.Unbound.Health(ctx, cfg)
	}
	if cfg.DNS.Provider == "dnsproxy" {
		return s.M.Dnsproxy.Health(ctx, cfg)
	}
	return nil
}

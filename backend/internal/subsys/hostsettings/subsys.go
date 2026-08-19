// Package hostsettings применяет системные параметры самого роутера.
package hostsettings

import (
	"context"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type Subsystem struct {
	Runner  system.Runner
	Systemd *system.Systemd
}

func New(r system.Runner) *Subsystem {
	return &Subsystem{Runner: r, Systemd: system.NewSystemd(r)}
}

// contendingUnits — демоны дистрибутива, которые правят то же, чем владеет
// netOS. Живая система обязана быть отражением конфигурации, и применённое
// состояние не может зависеть от того, кто записал последним.
//
// tuned входит в базовый набор облачных образов Debian и Ubuntu и в профиле
// virtual-guest переустанавливает сетевые параметры ядра. Стартует он позже
// netosd и откатывает подавление IPv6: аплинк снова получает disable_ipv6=0 и
// accept_ra=2. Панель при этом показывает «IPv6 выключен», потому что
// net.ipv6.conf.all.disable_ipv6 остаётся единицей — расходятся именно
// поинтерфейсные значения. Политики маршрутизации netOS работают только для
// IPv4, так что клиент, привязанный к VPN-каналу, ушёл бы в интернет мимо
// туннеля.
var contendingUnits = []string{"tuned.service"}

func (s *Subsystem) Name() string { return "system" }

func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	var actions []apply.Action
	// Проверка идёт по живой системе, а не по разнице конфигураций: чужой
	// демон мог подняться и после применения, и тогда план обязан это
	// показать, а не промолчать.
	for _, unit := range contendingUnits {
		if s.Systemd.IsActive(context.Background(), unit) {
			actions = append(actions, apply.Action{
				Kind:   "update",
				Target: "чужие демоны",
				Detail: unit + " переопределяет параметры netOS и будет остановлен",
			})
		}
	}
	if old == nil {
		return actions, nil
	}
	if old.System.Hostname != new.System.Hostname {
		actions = append(actions, apply.Action{Kind: "update", Target: "имя хоста", Detail: new.System.Hostname})
	}
	if old.System.Timezone != new.System.Timezone {
		actions = append(actions, apply.Action{Kind: "update", Target: "часовой пояс", Detail: new.System.Timezone})
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	// Гасится до всего остального: подсистемы sysctl и ipv6 идут следом, и
	// перезаписывать их работу после применения будет некому.
	for _, unit := range contendingUnits {
		if err := s.Systemd.Disable(ctx, unit); err != nil {
			return fmt.Errorf("остановка %s: %w", unit, err)
		}
	}
	if _, err := s.Runner.Run(ctx, "hostnamectl", "set-hostname", cfg.System.Hostname); err != nil {
		return fmt.Errorf("смена имени хоста: %w", err)
	}
	if _, err := s.Runner.Run(ctx, "timedatectl", "set-timezone", cfg.System.Timezone); err != nil {
		return fmt.Errorf("смена часового пояса: %w", err)
	}
	return nil
}

// Health намеренно не проверяет чужие демоны. Ошибка здесь откатывает всю
// конфигурацию, а вернувшийся tuned откатом не лечится: гасить его — дело
// Apply, который на неудаче и падает. Расхождение, возникшее позже, показывает
// netos plan.
func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	host, err := s.Runner.Run(ctx, "hostnamectl", "--static")
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) != cfg.System.Hostname {
		return fmt.Errorf("имя хоста не применено")
	}
	tz, err := s.Runner.Run(ctx, "timedatectl", "show", "--property=Timezone", "--value")
	if err != nil {
		return err
	}
	if strings.TrimSpace(tz) != cfg.System.Timezone {
		return fmt.Errorf("часовой пояс не применён")
	}
	return nil
}

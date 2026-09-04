// Package hostsettings применяет системные параметры самого роутера.
package hostsettings

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type Subsystem struct {
	Runner        system.Runner
	Systemd       *system.Systemd
	TimesyncdPath string
}

func New(r system.Runner) *Subsystem {
	return &Subsystem{
		Runner: r, Systemd: system.NewSystemd(r),
		TimesyncdPath: "/etc/systemd/timesyncd.conf.d/90-netos.conf",
	}
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
	return s.PlanContext(context.Background(), old, new)
}

func (s *Subsystem) PlanContext(ctx context.Context, old, new *config.Config) ([]apply.Action, error) {
	_ = old
	var actions []apply.Action
	// Проверка идёт по живой системе, а не по разнице конфигураций: чужой
	// демон мог подняться и после применения, и тогда план обязан это
	// показать, а не промолчать.
	for _, unit := range contendingUnits {
		if s.Systemd.IsActive(ctx, unit) {
			actions = append(actions, apply.Action{
				Kind:   "update",
				Target: "чужие демоны",
				Detail: unit + " переопределяет параметры netOS и будет остановлен",
			})
		}
	}
	if s.hostnameDrift(ctx, new) {
		actions = append(actions, apply.Action{Kind: "update", Target: "имя хоста", Detail: new.System.Hostname})
	}
	if s.timezoneDrift(ctx, new) {
		actions = append(actions, apply.Action{Kind: "update", Target: "часовой пояс", Detail: new.System.Timezone})
	}
	if s.ntpDrift(ctx, new) {
		detail := "синхронизация времени отключается"
		if new.System.NTP.Enabled {
			detail = "серверы: " + strings.Join(new.System.NTP.Servers, ", ")
		}
		actions = append(actions, apply.Action{Kind: "update", Target: "синхронизация времени", Detail: detail})
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
	if s.hostnameDrift(ctx, cfg) {
		if _, err := s.Runner.Run(ctx, "hostnamectl", "set-hostname", cfg.System.Hostname); err != nil {
			return fmt.Errorf("смена имени хоста: %w", err)
		}
	}
	if s.timezoneDrift(ctx, cfg) {
		if _, err := s.Runner.Run(ctx, "timedatectl", "set-timezone", cfg.System.Timezone); err != nil {
			return fmt.Errorf("смена часового пояса: %w", err)
		}
	}
	return s.applyNTP(ctx, cfg)
}

func (s *Subsystem) hostnameDrift(ctx context.Context, cfg *config.Config) bool {
	out, err := s.Runner.Run(ctx, "hostnamectl", "--static")
	return err != nil || strings.TrimSpace(out) != cfg.System.Hostname
}

func (s *Subsystem) timezoneDrift(ctx context.Context, cfg *config.Config) bool {
	out, err := s.Runner.Run(ctx, "timedatectl", "show", "--property=Timezone", "--value")
	return err != nil || strings.TrimSpace(out) != cfg.System.Timezone
}

func (s *Subsystem) renderNTP(cfg *config.Config) []byte {
	return []byte("# Сгенерировано netOS. Правки будут перезаписаны.\n[Time]\nNTP=" +
		strings.Join(cfg.System.NTP.Servers, " ") + "\nFallbackNTP=\n")
}

func (s *Subsystem) applyNTP(ctx context.Context, cfg *config.Config) error {
	if !cfg.System.NTP.Enabled {
		if !s.ntpDrift(ctx, cfg) {
			return nil
		}
		if err := s.Systemd.Disable(ctx, "systemd-timesyncd.service"); err != nil {
			return fmt.Errorf("отключение синхронизации времени: %w", err)
		}
		if err := os.Remove(s.TimesyncdPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("удаление настроек времени: %w", err)
		}
		return nil
	}
	fileChanged := system.FileChanged(s.TimesyncdPath, s.renderNTP(cfg))
	active := s.Systemd.IsActive(ctx, "systemd-timesyncd.service")
	enabled := s.unitEnabled(ctx, "systemd-timesyncd.service")
	if !fileChanged && active && enabled && s.timesyncdDirReady() {
		return nil
	}

	// netosd runs with UMask=0077. MkdirAll therefore creates a new drop-in
	// directory as 0700 unless we correct it explicitly, while timesyncd reads
	// configuration as the unprivileged systemd-timesync user.
	dir := filepath.Dir(s.TimesyncdPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("каталог настроек времени: %w", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("права каталога настроек времени: %w", err)
	}
	if fileChanged {
		if err := system.WriteFileAtomic(s.TimesyncdPath, s.renderNTP(cfg), 0o644); err != nil {
			return fmt.Errorf("настройка синхронизации времени: %w", err)
		}
	}
	if !active || !enabled {
		if _, err := s.Runner.Run(ctx, "systemctl", "enable", "--now", "systemd-timesyncd.service"); err != nil {
			return fmt.Errorf("запуск синхронизации времени: %w", err)
		}
	}
	if fileChanged && active {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", "systemd-timesyncd.service"); err != nil {
			return fmt.Errorf("перезапуск синхронизации времени: %w", err)
		}
	}
	return nil
}

func (s *Subsystem) ntpDrift(ctx context.Context, cfg *config.Config) bool {
	active := s.Systemd.IsActive(ctx, "systemd-timesyncd.service")
	enabled := s.unitEnabled(ctx, "systemd-timesyncd.service")
	if !cfg.System.NTP.Enabled {
		_, err := os.Stat(s.TimesyncdPath)
		return active || enabled || err == nil
	}
	return !active || !enabled || system.FileChanged(s.TimesyncdPath, s.renderNTP(cfg)) || !s.timesyncdDirReady()
}

func (s *Subsystem) timesyncdDirReady() bool {
	info, err := os.Stat(filepath.Dir(s.TimesyncdPath))
	return err == nil && info.IsDir() && info.Mode().Perm()&0o555 == 0o555
}

func (s *Subsystem) unitEnabled(ctx context.Context, unit string) bool {
	out, err := s.Runner.Run(ctx, "systemctl", "is-enabled", unit)
	if err != nil {
		return false
	}
	switch strings.TrimSpace(out) {
	case "enabled", "enabled-runtime", "static", "indirect", "generated", "alias":
		return true
	}
	return false
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
	if s.ntpDrift(ctx, cfg) {
		return fmt.Errorf("синхронизация времени не соответствует конфигурации")
	}
	if cfg.System.NTP.Enabled {
		servers, err := s.Runner.Run(ctx, "timedatectl", "show-timesync", "--property=SystemNTPServers", "--value")
		if err != nil {
			return fmt.Errorf("проверка серверов времени: %w", err)
		}
		if strings.Join(strings.Fields(servers), " ") != strings.Join(cfg.System.NTP.Servers, " ") {
			return fmt.Errorf("systemd-timesyncd не прочитал заданные серверы времени")
		}
	}
	return nil
}

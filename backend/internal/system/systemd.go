package system

import (
	"context"
	"fmt"
	"strings"
)

// Systemd управляет юнитами внешних демонов (dnsmasq, unbound, hostapd, ...).
type Systemd struct {
	R Runner
}

func NewSystemd(r Runner) *Systemd { return &Systemd{R: r} }

func (s *Systemd) systemctl(ctx context.Context, args ...string) error {
	_, err := s.R.Run(ctx, "systemctl", args...)
	return err
}

func (s *Systemd) Start(ctx context.Context, unit string) error {
	return s.systemctl(ctx, "start", unit)
}

func (s *Systemd) Stop(ctx context.Context, unit string) error {
	return s.systemctl(ctx, "stop", unit)
}

func (s *Systemd) Restart(ctx context.Context, unit string) error {
	return s.systemctl(ctx, "restart", unit)
}

// Reload посылает демону SIGHUP через systemd. Для тех демонов, что умеют
// перечитывать конфиг на лету, это предпочтительнее перезапуска: клиенты не
// теряют аренды DHCP и не сбрасывается кэш DNS.
func (s *Systemd) Reload(ctx context.Context, unit string) error {
	return s.systemctl(ctx, "reload", unit)
}

// ReloadOrRestart пробует мягкую перезагрузку и откатывается к перезапуску.
func (s *Systemd) ReloadOrRestart(ctx context.Context, unit string) error {
	return s.systemctl(ctx, "reload-or-restart", unit)
}

func (s *Systemd) Enable(ctx context.Context, unit string) error {
	return s.systemctl(ctx, "enable", unit)
}

// Disable останавливает и выключает юнит. Используется, когда пользователь
// переключил провайдера DHCP или DNS: старый демон не должен остаться висеть
// на 53 порту и мешать новому.
func (s *Systemd) Disable(ctx context.Context, unit string) error {
	if err := s.systemctl(ctx, "disable", "--now", unit); err != nil {
		// Отсутствующий юнит — не ошибка: пакет мог быть не установлен.
		if strings.Contains(err.Error(), "not loaded") || strings.Contains(err.Error(), "No such file") {
			return nil
		}
		return err
	}
	return nil
}

func (s *Systemd) IsActive(ctx context.Context, unit string) bool {
	out, err := s.R.Run(ctx, "systemctl", "is-active", unit)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "active"
}

func (s *Systemd) DaemonReload(ctx context.Context) error {
	return s.systemctl(ctx, "daemon-reload")
}

// Packages ставит недостающие пакеты. Компоненты вроде xray, strongswan или
// hostapd не входят в базовую установку и подтягиваются в момент, когда
// пользователь включает соответствующую функцию в панели.
type Packages struct {
	R Runner
}

func NewPackages(r Runner) *Packages { return &Packages{R: r} }

// Installed проверяет наличие пакета через dpkg-query.
func (p *Packages) Installed(ctx context.Context, pkg string) bool {
	out, err := p.R.Run(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
	if err != nil {
		return false
	}
	return strings.Contains(out, "install ok installed")
}

// Ensure ставит пакеты, которых нет. Возвращает список установленных, чтобы
// панель могла показать пользователю, что именно было доустановлено.
func (p *Packages) Ensure(ctx context.Context, pkgs ...string) ([]string, error) {
	var missing []string
	for _, pkg := range pkgs {
		if !p.Installed(ctx, pkg) {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	args := append([]string{"-o", "DPkg::Lock::Timeout=60", "install", "-y", "--no-install-recommends"}, missing...)
	if _, err := p.R.Run(ctx, "apt-get", args...); err != nil {
		return nil, fmt.Errorf("установка пакетов %s: %w", strings.Join(missing, ", "), err)
	}
	return missing, nil
}

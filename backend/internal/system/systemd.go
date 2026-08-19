package system

import (
	"context"
	"fmt"
	"os"
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
	if s.alreadyDisabled(ctx, unit) {
		return nil
	}
	// disable и stop разделены намеренно. Для служб, унаследованных от SysV,
	// systemctl перенаправляет disable в update-rc.d и останавливать демона не
	// идёт: --now в этом случае молча ничего не делает. Так ведёт себя xl2tpd
	// в Debian, и без отдельного stop чужой демон остался бы висеть на порту,
	// который нужен netOS.
	if err := s.systemctl(ctx, "disable", unit); err != nil && !unitMissing(err) {
		return err
	}
	if err := s.systemctl(ctx, "stop", unit); err != nil && !unitMissing(err) {
		return err
	}
	// Штатный юнит успевает стартовать из postinst пакета — раньше, чем netOS
	// вообще узнаёт об установке, — и падает на занятом порту. Погашенный, он
	// так и остаётся в состоянии failed: systemctl показывает красную строку,
	// а вся система — degraded, хотя ничего не сломано. Состояние сбрасываем.
	_ = s.systemctl(ctx, "reset-failed", unit)

	// Проверяем результат, а не коды возврата: цель — чтобы демон не работал.
	if s.IsActive(ctx, unit) {
		return fmt.Errorf("служба %s продолжает работать после остановки", unit)
	}
	return nil
}

// alreadyDisabled сообщает, что делать нечего: юнит не работает и не включён.
//
// Проверка нужна не ради скорости. netOS гасит чужие юниты при каждом
// применении конфигурации, и почти всегда они уже погашены. Но systemctl
// disable для службы, унаследованной от SysV, идёт через systemd-sysv-install
// и заставляет systemd перечитать юниты, а вместе с ними прогнать все
// генераторы системы — включая чужие, чьи предупреждения заполняют журнал.
// Один пакет isc-dhcp-server с init-скриптом без нативного юнита давал по
// полтора десятка таких записей на каждое применение. Опрос состояния таких
// последствий не имеет.
// Пропускаем работу только при однозначно известном состоянии. Коды возврата
// здесь ничего не значат — «inactive» и «disabled» systemctl сообщает вместе с
// ненулевым кодом, — поэтому судим по выводу. Пустой вывод означает, что
// ответа не было: работу в этом случае делаем, а не считаем сделанной.
func (s *Systemd) alreadyDisabled(ctx context.Context, unit string) bool {
	active, _ := s.R.Run(ctx, "systemctl", "is-active", unit)
	if strings.TrimSpace(active) != "inactive" {
		// active, activating, failed — есть что останавливать или сбрасывать.
		return false
	}
	enabled, _ := s.R.Run(ctx, "systemctl", "is-enabled", unit)
	switch strings.TrimSpace(enabled) {
	case "disabled", "masked", "masked-runtime", "static", "generated", "transient":
		return true
	}
	return false
}

// unitMissing распознаёт отказ из-за отсутствующего юнита.
//
// Для Disable это не ошибка, а уже достигнутая цель: юнита нет — значит, демон
// точно не работает. Формулировки systemd различаются по версиям и по глаголу
// («does not exist» на disable, «not loaded» на stop), поэтому сверяемся со
// всеми: одна пропущенная фраза роняет применение целиком и не даёт netosd
// запуститься вовсе.
func unitMissing(err error) bool {
	msg := err.Error()
	for _, phrase := range []string{"does not exist", "not loaded", "No such file", "not found"} {
		if strings.Contains(msg, phrase) {
			return true
		}
	}
	return false
}

func (s *Systemd) IsActive(ctx context.Context, unit string) bool {
	out, err := s.R.Run(ctx, "systemctl", "is-active", unit)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "active"
}

// ActiveUnits возвращает имена работающих юнитов, подходящих под шаблон
// (например «netos-*.service»). Одним запросом, а не опросом по одному: панель
// спрашивает состояние всех компонентов сразу и делает это регулярно, а каждый
// systemctl is-active — это отдельный процесс.
//
// Шаблон обязателен и здесь же передаётся systemctl: юниты аплинков названы по
// идентификатору канала, и заранее их имён никто не знает.
func (s *Systemd) ActiveUnits(ctx context.Context, pattern string) []string {
	out, err := s.R.Run(ctx, "systemctl", "list-units", "--type=service",
		"--state=active", "--no-legend", "--plain", "--no-pager", pattern)
	if err != nil {
		return nil
	}
	var units []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		units = append(units, fields[0])
	}
	return units
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
	// Демонов запускает netOS собственными юнитами, поэтому postinst пакета
	// запускать их не должен: у него для этого нет ни конфига, ни причины.
	release, err := holdDaemons()
	if err != nil {
		return nil, err
	}
	defer release()

	args := append([]string{"-o", "DPkg::Lock::Timeout=60", "install", "-y", "--no-install-recommends"}, missing...)
	if _, err := p.R.Run(ctx, "apt-get", args...); err != nil {
		return nil, fmt.Errorf("установка пакетов %s: %w", strings.Join(missing, ", "), err)
	}
	return missing, nil
}

// policyRCPath — скрипт, у которого Debian спрашивает разрешения, прежде чем
// postinst пакета запустит демона. Код возврата 101 означает запрет.
const policyRCPath = "/usr/sbin/policy-rc.d"

// holdDaemons запрещает запуск демонов на время установки пакета и возвращает
// функцию, снимающую запрет.
//
// Без этого пакет поднимает штатного демона со своим конфигом сразу после
// распаковки — раньше, чем netOS успевает его выключить, и всегда со своим
// конфигом, а не с генерируемым. Ничем хорошим это не кончается: dhcpd падает
// с «Not configured to listen on any interfaces», unbound — на отсутствующем
// якоре DNSSEC по пути из его же конфига, systemd крутит перезапуски, пока
// netOS не доберётся до Disable, а вспомогательные юниты вроде
// unbound-resolvconf остаются в состоянии failed. От установки одного
// компонента в журнале остаётся полоса ошибок, за которой не видно настоящих.
//
// Чужой policy-rc.d не трогаем: он принадлежит не нам, и вернуть его на место
// после подмены надёжно нельзя. Запрет в этом случае просто не ставится.
func holdDaemons() (func(), error) {
	if _, err := os.Stat(policyRCPath); err == nil {
		return func() {}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	script := "#!/bin/sh\n" +
		"# Создано netOS на время установки пакета и удаляется сразу после неё.\n" +
		"# Демонами управляет netOS собственными юнитами.\n" +
		"exit 101\n"
	if err := WriteFileAtomic(policyRCPath, []byte(script), 0o755); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(policyRCPath) }, nil
}

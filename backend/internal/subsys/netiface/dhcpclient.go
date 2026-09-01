package netiface

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Клиент DHCP для аплинка.
//
// Используется udhcpc из busybox, а не dhclient или dhcpcd, по трём причинам:
// он уже есть в базовой системе, он не трогает /etc/resolv.conf и прочие общие
// файлы, и его поведение полностью описывается одним скриптом, который мы
// генерируем сами. Для роутера, где вся конфигурация обязана быть
// предсказуемой, это важнее богатых возможностей больших клиентов.

var (
	dhcpScriptDir  = "/var/lib/netos/generated"
	systemdUnitDir = "/etc/systemd/system"
	dhcpRuntimeDir = "/run"
)

// renderDHCPScript собирает скрипт-обработчик событий udhcpc.
//
// Метрика маршрута зашивается в скрипт: она разная у разных аплинков и именно
// ею определяется, какой из них станет основным при нескольких подключениях.
func renderDHCPScript(metric int) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("#!/bin/sh")
	w("# Сгенерировано netOS. Обработчик событий udhcpc.")
	w("# Управление DNS намеренно отсутствует: резолвером роутера владеет netOS,")
	w("# и переписывание resolv.conf клиентом DHCP ломало бы его настройки.")
	w("")
	w("METRIC=%d", metric)
	w("STATE=%s/netos-dhcp-$interface.address", dhcpRuntimeDir)
	w("")
	w("case \"$1\" in")
	w("    deconfig)")
	w("        if [ -s \"$STATE\" ]; then")
	w("            old=$(cat \"$STATE\")")
	w("            ip -4 addr del \"$old\" dev \"$interface\" 2>/dev/null || true")
	w("        fi")
	w("        ip -4 route flush default dev \"$interface\" proto dhcp 2>/dev/null || true")
	w("        rm -f \"$STATE\"")
	w("        ip link set \"$interface\" up")
	w("        ;;")
	w("")
	w("    bound|renew)")
	w("        # Адрес назначаем заново, а не добавляем: аренда могла смениться,")
	w("        # и два адреса на интерфейсе привели бы к непредсказуемой маршрутизации.")
	w("        if [ -s \"$STATE\" ]; then")
	w("            old=$(cat \"$STATE\")")
	w("            [ \"$old\" = \"$ip/$mask\" ] || ip -4 addr del \"$old\" dev \"$interface\" 2>/dev/null || true")
	w("        fi")
	w("        ip -4 addr replace \"$ip/$mask\" dev \"$interface\"")
	w("        ip link set \"$interface\" up")
	w("")
	w("        if [ -n \"$router\" ]; then")
	w("            for gw in $router; do")
	w("                ip -4 route replace default via \"$gw\" dev \"$interface\" metric \"$METRIC\" proto dhcp")
	w("                break")
	w("            done")
	w("        fi")
	w("")
	w("        if [ -n \"$mtu\" ]; then")
	w("            ip link set \"$interface\" mtu \"$mtu\" 2>/dev/null")
	w("        fi")
	w("")
	w("        # Маркер готовности публикуем последним: Health не должен")
	w("        # принять аренду до установки маршрута и MTU.")
	w("        printf '%%s\\n' \"$ip/$mask\" > \"$STATE\"")
	w("")
	w("        logger -t netos-dhcp \"аплинк $interface получил $ip/$mask, шлюз ${router:-нет}\"")
	w("        ;;")
	w("")
	w("    leasefail|nak)")
	w("        logger -t netos-dhcp \"аплинк $interface: аренда не получена ($1)\"")
	w("        ;;")
	w("esac")
	w("")
	w("exit 0")

	return b.String()
}

// dhcpUnit собирает systemd-юнит клиента для одного интерфейса.
func dhcpUnit(iface, scriptPath string) string {
	return `[Unit]
Description=netOS: клиент DHCP на интерфейсе ` + iface + `
After=network-pre.target
BindsTo=sys-subsystem-net-devices-` + systemdEscape(iface) + `.device
After=sys-subsystem-net-devices-` + systemdEscape(iface) + `.device

[Service]
Type=simple
# -f держит клиента на переднем плане, чтобы systemd следил за ним сам,
# -t и -T задают число и интервал попыток, -S пишет события в syslog.
ExecStart=/usr/bin/busybox udhcpc -f -i ` + iface + ` -s ` + scriptPath + ` -t 5 -T 3 -S
ExecStopPost=/usr/bin/env interface=` + iface + ` ` + scriptPath + ` deconfig
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
}

// systemdEscape приводит имя интерфейса к виду, принятому в именах устройств
// systemd. Для обычных имён вроде eth0 или enp0s3 замен не требуется, но дефис
// в именах мостов экранируется.
func systemdEscape(name string) string {
	return strings.ReplaceAll(name, "-", `\x2d`)
}

// ensureDHCPClientFiles создаёт скрипт и юнит для интерфейса.
func (s *WAN) ensureDHCPClientFiles(ctx context.Context, w config.WAN, iface string) (string, bool, error) {
	scriptPath := filepath.Join(dhcpScriptDir, "udhcpc-"+iface+".sh")
	script := []byte(renderDHCPScript(w.Metric))
	scriptChanged, err := system.WriteFileAtomicIfChanged(scriptPath, script, 0o755)
	if err != nil {
		return "", false, fmt.Errorf("запись скрипта DHCP: %w", err)
	}

	unitName := "netos-dhcp-" + iface + ".service"
	unitPath := filepath.Join(systemdUnitDir, unitName)
	unit := []byte(dhcpUnit(iface, scriptPath))
	unitChanged, err := system.WriteFileAtomicIfChanged(unitPath, unit, 0o644)
	if err != nil {
		return "", false, fmt.Errorf("запись юнита DHCP: %w", err)
	}
	if unitChanged {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return "", false, err
		}
	}
	return unitName, scriptChanged || unitChanged, nil
}

// cleanupDHCPClients останавливает и удаляет сгенерированные units для
// аплинков, которых больше нет в конфигурации.
func (s *WAN) cleanupDHCPClients(ctx context.Context, wanted map[string]bool) error {
	units, err := filepath.Glob(filepath.Join(systemdUnitDir, "netos-dhcp-*.service"))
	if err != nil {
		return err
	}
	changed := false
	for _, unitPath := range units {
		base := filepath.Base(unitPath)
		iface := strings.TrimSuffix(strings.TrimPrefix(base, "netos-dhcp-"), ".service")
		if wanted[iface] {
			continue
		}
		if err := s.stopDHCPClient(ctx, iface); err != nil {
			return err
		}
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("удаление %s: %w", unitPath, err)
		}
		scriptPath := filepath.Join(dhcpScriptDir, "udhcpc-"+iface+".sh")
		if err := os.Remove(scriptPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("удаление %s: %w", scriptPath, err)
		}
		changed = true
	}
	// Частично завершившийся прошлый Apply мог успеть записать скрипт, но не
	// unit. Такой артефакт тоже принадлежит netOS и не должен жить вечно.
	scripts, err := filepath.Glob(filepath.Join(dhcpScriptDir, "udhcpc-*.sh"))
	if err != nil {
		return err
	}
	for _, scriptPath := range scripts {
		base := filepath.Base(scriptPath)
		iface := strings.TrimSuffix(strings.TrimPrefix(base, "udhcpc-"), ".sh")
		if wanted[iface] {
			continue
		}
		if err := os.Remove(scriptPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("удаление %s: %w", scriptPath, err)
		}
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	return nil
}

package netiface

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

// Клиент PPPoE для аплинка.
//
// Провайдер, выдающий интернет по логину и паролю, — самый обычный случай для
// домашнего подключения, и без него netOS на такой линии просто не поднимется.
//
// Соединение держит pppd с плагином rp-pppoe: он работает в ядре и не требует
// отдельного демона поверх. Как и клиент DHCP, каждый аплинк получает свой
// systemd-юнит, чтобы перезапуск netosd не рвал установленную сессию.
const pppoeConfDir = "/var/lib/netos/generated"

// PPPoEInterface возвращает имя интерфейса, который поднимет аплинк.
//
// Имя обязано быть предсказуемым: на него ссылаются зоны файрволла, и
// «какой-нибудь ppp0» здесь не годится — при двух аплинках номера зависели бы
// от порядка подключения.
func PPPoEInterface(wanID string) string { return "ppp-" + wanID }

// renderPPPoEConf собирает файл параметров pppd для одного аплинка.
func renderPPPoEConf(w config.WAN, iface string) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	line("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	line("")
	line("plugin rp-pppoe.so")
	// Физический интерфейс, на котором идёт разговор с концентратором.
	line("nic-%s", iface)
	line("ifname %s", PPPoEInterface(w.ID))
	line("")

	line("user %q", w.Username)
	// Пароль лежит здесь, а не в общесистемном /etc/ppp/pap-secrets: этот файл
	// netOS перезаписывает целиком и держит с правами 0600, а общий разделяется
	// с другими потребителями ppp, и вычищать оттуда свои строки надёжно нельзя.
	line("password %q", w.Password)
	// Пароль не должен попадать в журнал.
	line("hide-password")
	// Себя провайдеру доказываем, а от него аутентификации не требуем: её
	// запрос сломал бы соединение с большинством концентраторов.
	line("noauth")
	line("")

	if w.Service != "" {
		line("rp_pppoe_service %q", w.Service)
	}
	if w.AC != "" {
		line("rp_pppoe_ac %q", w.AC)
	}

	// Адрес выдаёт провайдер, свой не предлагаем.
	line("noipdefault")
	line("defaultroute")
	// Метрика решает, какой аплинк станет основным при нескольких подключениях.
	line("defaultroute-metric %d", w.Metric)
	// replacedefaultroute намеренно не используется: он затирает маршруты
	// других аплинков, а приоритет между ними — дело метрики.
	line("")

	// resolv.conf роутера принадлежит netOS: провайдерские серверы имён
	// подставляются через конфигурацию резолвера, а не поверх неё.
	line("# usepeerdns не указан намеренно: резолвером роутера владеет netOS")

	// IPv6 подавляется на всех уровнях — не даём поднять его и здесь.
	if w.MTU > 0 {
		line("mtu %d", w.MTU)
		line("mru %d", w.MTU)
	} else {
		// 1492 = 1500 минус 8 байт заголовка PPPoE.
		line("mtu 1492")
		line("mru 1492")
	}
	line("noipv6")
	line("")

	// Обрыв линии обнаруживаем сами: без echo pppd будет считать мёртвую
	// сессию живой, пока провайдер не пришлёт что-нибудь.
	line("lcp-echo-interval 20")
	line("lcp-echo-failure 3")
	// Переподключаемся бесконечно: аплинк не должен требовать вмешательства
	// человека после ночного обрыва у провайдера.
	line("persist")
	line("maxfail 0")
	line("holdoff 5")
	return b.String()
}

// pppoeUnit собирает systemd-юнит клиента для одного аплинка.
func pppoeUnit(w config.WAN, iface, confPath string) string {
	return `[Unit]
Description=netOS: PPPoE-аплинк ` + w.Name + ` на интерфейсе ` + iface + `
After=network-pre.target
BindsTo=sys-subsystem-net-devices-` + systemdEscape(iface) + `.device
After=sys-subsystem-net-devices-` + systemdEscape(iface) + `.device

[Service]
Type=simple
# nodetach оставляет pppd на переднем плане, чтобы за перезапуском следил
# systemd, а не встроенный в pppd механизм демонизации.
ExecStart=/usr/sbin/pppd file ` + confPath + ` nodetach
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
}

// ensurePPPoE создаёт файлы и поднимает клиента для одного аплинка.
func (s *WAN) ensurePPPoE(ctx context.Context, w config.WAN, iface string) error {
	confPath := pppoeConfPath(w.ID)
	conf := []byte(renderPPPoEConf(w, iface))
	// 0600: в файле пароль от провайдера.
	if err := system.WriteFileAtomic(confPath, conf, 0o600); err != nil {
		return fmt.Errorf("запись конфигурации PPPoE: %w", err)
	}

	unitName := pppoeUnitName(w.ID)
	unitPath := filepath.Join("/etc/systemd/system", unitName)
	unit := []byte(pppoeUnit(w, iface, confPath))
	unitChanged := system.FileChanged(unitPath, unit)
	if unitChanged {
		if err := system.WriteFileAtomic(unitPath, unit, 0o644); err != nil {
			return fmt.Errorf("запись юнита PPPoE: %w", err)
		}
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}

	if _, err := s.Runner.Run(ctx, "systemctl", "enable", unitName); err != nil {
		return err
	}
	// Рвать установленную сессию без причины нельзя: переподключение к
	// провайдеру занимает секунды и меняет внешний адрес. Перезапускаем только
	// когда изменились параметры или клиент не работает.
	if !unitChanged && !s.confChanged(confPath, conf) && s.unitActive(ctx, unitName) {
		return nil
	}
	if _, err := s.Runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
		return fmt.Errorf("запуск PPPoE на %s: %w", iface, err)
	}
	return nil
}

// confChanged сравнивает конфигурацию с уже записанной. Вызывается после
// записи, поэтому сверяемся со снимком, сделанным до неё.
func (s *WAN) confChanged(path string, conf []byte) bool {
	return s.pppoePrevious[path] != string(conf)
}

func (s *WAN) unitActive(ctx context.Context, unit string) bool {
	out, err := s.Runner.Run(ctx, "systemctl", "is-active", unit)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "active"
}

func pppoeConfPath(wanID string) string {
	return filepath.Join(pppoeConfDir, "pppoe-"+wanID+".conf")
}

func pppoeUnitName(wanID string) string { return "netos-pppoe-" + wanID + ".service" }

// cleanupPPPoE останавливает и удаляет клиентов аплинков, которых больше нет в
// конфигурации.
func (s *WAN) cleanupPPPoE(ctx context.Context, wanted map[string]bool) error {
	units, err := filepath.Glob("/etc/systemd/system/netos-pppoe-*.service")
	if err != nil {
		return err
	}
	changed := false
	for _, unitPath := range units {
		base := filepath.Base(unitPath)
		id := strings.TrimSuffix(strings.TrimPrefix(base, "netos-pppoe-"), ".service")
		if wanted[id] {
			continue
		}
		// Отсутствующий юнит не ошибка: до него мог не дойти прошлый запуск.
		_, _ = s.Runner.Run(ctx, "systemctl", "disable", "--now", base)
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("удаление %s: %w", unitPath, err)
		}
		if err := os.Remove(pppoeConfPath(id)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("удаление %s: %w", pppoeConfPath(id), err)
		}
		changed = true
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	return nil
}

// readPPPoEConfs снимает состояние конфигураций до записи новых, чтобы потом
// понять, что именно изменилось, и не перезапускать живые сессии зря.
func (s *WAN) readPPPoEConfs(cfg *config.Config) {
	s.pppoePrevious = map[string]string{}
	for _, w := range cfg.WANs {
		if w.Proto != "pppoe" {
			continue
		}
		path := pppoeConfPath(w.ID)
		if data, err := os.ReadFile(path); err == nil {
			s.pppoePrevious[path] = string(data)
		}
	}
}

// waitPPPoE ждёт, пока сессия установится.
//
// Дозвон до концентратора занимает секунды, а проверка после применения идёт
// сразу за ним. Без ожидания движок счёл бы верную конфигурацию неудачной и
// откатил её — то есть PPPoE нельзя было бы включить в принципе.
func (s *WAN) waitPPPoE(ctx context.Context, w config.WAN) error {
	timeout := s.PPPoETimeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	interval := s.PPPoePoll
	if interval <= 0 {
		interval = time.Second
	}

	iface := PPPoEInterface(w.ID)
	deadline := time.Now().Add(timeout)
	for {
		if addrs, err := addressesOf(ctx, s.Runner, iface); err == nil && len(addrs) > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
	return fmt.Errorf(
		"аплинк %s не поднялся за %s: проверьте логин, пароль и то, что кабель провайдера включён в нужный порт",
		w.Name, timeout)
}

package netiface

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Клиент L2TP для аплинка.
//
// Речь именно о подключении к провайдеру, а не о туннеле до чужой сети:
// провайдер сначала выдаёт адрес в своей локальной сети, а интернет живёт за
// концентратором, до которого надо дозвониться логином и паролем.
//
// Схема: xl2tpd поднимает туннель и отдаёт pppd псевдотерминал, дальше всё как
// у PPPoE. Переподключением занимается xl2tpd, поэтому в параметрах pppd нет
// persist: два механизма перезвона мешали бы друг другу.

// l2tpUnitName возвращает имя юнита туннеля.
func l2tpUnitName(wanID string) string { return "netos-l2tp-" + wanID + ".service" }

func l2tpConfPath(wanID string) string {
	// The path is embedded in a Linux systemd unit even when tests or release
	// tooling run on another OS, so it must always use forward slashes.
	return path.Join(pppoeConfDir, "l2tp-"+wanID+".conf")
}

func l2tpPPPPath(wanID string) string {
	return path.Join(pppoeConfDir, "l2tp-"+wanID+".ppp")
}

// maxRedials — число попыток перезвона, которого хватит навсегда: при
// интервале в 5 секунд это больше трёхсот лет.
const maxRedials = 2000000000

// underlayMetric — метрика маршрута по умолчанию через сеть провайдера.
//
// Заведомо хуже, чем у туннеля: пока туннель не поднят, интернета через эту
// сеть всё равно нет, а как только он появится, маршрут через него обязан
// выиграть. Разрыв в 10 оставляет место соседним аплинкам.
func underlayMetric(w config.WAN) int { return w.Metric + 10 }

// underlayWAN описывает подложку как обычный аплинк: тем же клиентом DHCP и
// тем же кодом статики, что и у остальных, только с худшей метрикой.
func underlayWAN(w config.WAN) config.WAN {
	u := w
	u.Metric = underlayMetric(w)
	return u
}

// L2TPInterface — имя интерфейса сессии. Совпадает по форме с PPPoE, потому
// что на него так же ссылаются зоны файрволла.
func L2TPInterface(wanID string) string { return "ppp-" + wanID }

// renderL2TPConf собирает конфигурацию xl2tpd для одного аплинка.
func renderL2TPConf(w config.WAN) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	line("; Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	line("[global]")
	// Роутер здесь только клиент. Слушать входящие туннели не нужно, а на
	// аплинке это был бы открытый наружу порт.
	line("port = 1701")
	line("access control = no")
	line("")

	line("[lac %s]", w.ID)
	line("lns = %s", w.Server)
	line("name = %s", w.Username)
	line("pppoptfile = %s", l2tpPPPPath(w.ID))
	// Провайдеры используют и PAP, и CHAP: не навязываем ни того, ни другого,
	// иначе часть концентраторов откажет.
	line("require pap = no")
	line("require chap = no")
	line("refuse pap = no")
	line("refuse chap = no")
	// Себя доказываем, от концентратора аутентификации не требуем.
	line("require authentication = no")
	// Дозвон при старте и практически бесконечный перезвон: ночной обрыв у
	// провайдера не должен требовать вмешательства человека.
	//
	// Ноль здесь не работает: xl2tpd отвергает конфигурацию целиком с «rmax
	// value must be at least 1», а исчерпав попытки, он не завершается — то
	// есть перезапуск юнита туннель не вернул бы. Поэтому берём заведомо
	// недостижимое число.
	line("autodial = yes")
	line("redial = yes")
	line("redial timeout = 5")
	line("max redials = %d", maxRedials)
	line("length bit = yes")
	return b.String()
}

// renderL2TPPPP собирает параметры pppd для сессии внутри туннеля.
func renderL2TPPPP(w config.WAN) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	line("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	line("ifname %s", L2TPInterface(w.ID))
	line("")
	line("user %q", w.Username)
	// Пароль здесь, а не в общесистемном /etc/ppp/chap-secrets: этот файл netOS
	// перезаписывает целиком и держит с правами 0600.
	line("password %q", w.Password)
	line("hide-password")
	line("noauth")
	line("")

	line("noipdefault")
	line("defaultroute")
	line("defaultroute-metric %d", w.Metric)
	line("")

	// Туннель добавляет свои заголовки поверх IP: 1500 минус IP, UDP, L2TP и
	// PPP. 1400 — значение, с которым работают все известные провайдеры.
	mtu := w.MTU
	if mtu <= 0 {
		mtu = 1400
	}
	line("mtu %d", mtu)
	line("mru %d", mtu)
	line("noipv6")
	line("")

	line("lcp-echo-interval 20")
	line("lcp-echo-failure 3")
	// persist отсутствует намеренно: перезвоном занимается xl2tpd, и два
	// механизма мешали бы друг другу.
	line("# перезвон — за xl2tpd, поэтому persist здесь не нужен")
	// nodetach и pppol2tp передаёт сам xl2tpd в командной строке, а опции lock
	// в pppd 2.5 уже нет: она относилась к файлам блокировки UUCP и к
	// псевдотерминалу неприменима. Указывать её значило бы не запустить pppd
	// вовсе — «unrecognized option».
	return b.String()
}

func l2tpUnit(w config.WAN) string {
	return `[Unit]
Description=netOS: L2TP-аплинк ` + w.Name + `
After=network-pre.target
Wants=network-pre.target

[Service]
Type=simple
ExecStart=/usr/sbin/xl2tpd -D -c ` + l2tpConfPath(w.ID) + ` -p /run/netos-l2tp-` + w.ID + `.pid -C /run/netos-l2tp-` + w.ID + `.ctl
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
}

// ensureL2TP поднимает туннель для одного аплинка.
func (s *WAN) ensureL2TP(ctx context.Context, w config.WAN, iface string) error {
	// Маршрут до концентратора обязан идти мимо туннеля. Как только pppd
	// поставит маршрут по умолчанию через ppp, пакеты самого туннеля пошли бы
	// в него же — соединение схлопнулось бы на первом же переподключении.
	if err := s.routeToLNS(ctx, w, iface); err != nil {
		return err
	}

	ppp := []byte(renderL2TPPPP(w))
	// 0600: в файле пароль от провайдера.
	if err := system.WriteFileAtomic(l2tpPPPPath(w.ID), ppp, 0o600); err != nil {
		return fmt.Errorf("запись параметров pppd для L2TP: %w", err)
	}
	conf := []byte(renderL2TPConf(w))
	changed := system.FileChanged(l2tpConfPath(w.ID), conf) || s.confChanged(l2tpPPPPath(w.ID), ppp)
	if err := system.WriteFileAtomic(l2tpConfPath(w.ID), conf, 0o600); err != nil {
		return fmt.Errorf("запись конфигурации xl2tpd: %w", err)
	}

	unitName := l2tpUnitName(w.ID)
	unitPath := filepath.Join("/etc/systemd/system", unitName)
	unit := []byte(l2tpUnit(w))
	if system.FileChanged(unitPath, unit) {
		if err := system.WriteFileAtomic(unitPath, unit, 0o644); err != nil {
			return fmt.Errorf("запись юнита L2TP: %w", err)
		}
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		changed = true
	}

	if _, err := s.Runner.Run(ctx, "systemctl", "enable", unitName); err != nil {
		return err
	}
	// Рвать установленный туннель без причины нельзя: переподключение занимает
	// секунды и меняет внешний адрес.
	if !changed && s.unitActive(ctx, unitName) {
		return nil
	}
	if _, err := s.Runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
		return fmt.Errorf("запуск L2TP до %s: %w", w.Server, err)
	}
	return nil
}

// routeToLNS прокладывает маршрут до концентратора через сеть провайдера.
func (s *WAN) routeToLNS(ctx context.Context, w config.WAN, iface string) error {
	gateway := w.Gateway
	if w.Underlay != "static" {
		// Адрес под туннелем получен по DHCP — шлюз известен только из аренды,
		// поэтому читаем его из таблицы маршрутизации.
		found, err := s.underlayGateway(ctx, iface)
		if err != nil {
			return err
		}
		gateway = found
	}
	if gateway == "" {
		return fmt.Errorf(
			"аплинк %s: не найден шлюз сети провайдера, через который идти к %s", w.Name, w.Server)
	}

	addrs, err := net.LookupHost(w.Server)
	if err != nil {
		return fmt.Errorf("не удалось определить адрес концентратора %s: %w", w.Server, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			// IPv6 подавляется на всех уровнях, туннель по нему не поднимаем.
			continue
		}
		if _, err := s.Runner.Run(ctx, "ip", "route", "replace", ip.String()+"/32",
			"via", gateway, "dev", iface, "proto", fmt.Sprint(config.RouteProto)); err != nil {
			return fmt.Errorf("маршрут до концентратора %s: %w", ip, err)
		}
	}
	return nil
}

// underlayGateway читает шлюз, который выдал клиент DHCP на интерфейсе под
// туннелем.
func (s *WAN) underlayGateway(ctx context.Context, iface string) (string, error) {
	out, err := s.Runner.Run(ctx, "ip", "-4", "route", "show", "default", "dev", iface)
	if err != nil {
		return "", fmt.Errorf("чтение шлюза на %s: %w", iface, err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "via" {
				return fields[i+1], nil
			}
		}
	}
	return "", nil
}

// cleanupL2TP убирает туннели аплинков, которых больше нет в конфигурации.
func (s *WAN) cleanupL2TP(ctx context.Context, wanted map[string]bool) error {
	units, err := filepath.Glob("/etc/systemd/system/netos-l2tp-*.service")
	if err != nil {
		return err
	}
	changed := false
	for _, unitPath := range units {
		base := filepath.Base(unitPath)
		id := strings.TrimSuffix(strings.TrimPrefix(base, "netos-l2tp-"), ".service")
		if wanted[id] {
			continue
		}
		_, _ = s.Runner.Run(ctx, "systemctl", "disable", "--now", base)
		for _, path := range []string{unitPath, l2tpConfPath(id), l2tpPPPPath(id)} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("удаление %s: %w", path, err)
			}
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

// readL2TPConfs снимает состояние параметров pppd до записи новых, чтобы не
// рвать живой туннель, когда ничего не изменилось.
func (s *WAN) readL2TPConfs(cfg *config.Config) {
	for _, w := range cfg.WANs {
		if w.Proto != "l2tp" {
			continue
		}
		path := l2tpPPPPath(w.ID)
		if data, err := os.ReadFile(path); err == nil {
			s.pppoePrevious[path] = string(data)
		}
	}
}

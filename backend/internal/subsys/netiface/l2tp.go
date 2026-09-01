package netiface

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
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
	pppChanged, err := system.WriteFileAtomicIfChanged(l2tpPPPPath(w.ID), ppp, 0o600)
	if err != nil {
		return fmt.Errorf("запись параметров pppd для L2TP: %w", err)
	}
	conf := []byte(renderL2TPConf(w))
	confChanged, err := system.WriteFileAtomicIfChanged(l2tpConfPath(w.ID), conf, 0o600)
	if err != nil {
		return fmt.Errorf("запись конфигурации xl2tpd: %w", err)
	}
	changed := pppChanged || confChanged

	unitName := l2tpUnitName(w.ID)
	unitPath := filepath.Join(systemdUnitDir, unitName)
	unit := []byte(l2tpUnit(w))
	unitChanged, err := system.WriteFileAtomicIfChanged(unitPath, unit, 0o644)
	if err != nil {
		return fmt.Errorf("запись юнита L2TP: %w", err)
	}
	if unitChanged {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		changed = true
	}

	if !s.unitEnabled(ctx, unitName) {
		if _, err := s.Runner.Run(ctx, "systemctl", "enable", unitName); err != nil {
			return err
		}
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
	foundIPv4 := false
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			// IPv6 подавляется на всех уровнях, туннель по нему не поднимаем.
			continue
		}
		foundIPv4 = true
		item := ownedLNSRoute{Destination: ip.String() + "/32", Gateway: gateway, Interface: iface}
		if err := s.rememberLNSRoute(item); err != nil {
			return err
		}
		if s.lnsRouteWanted == nil {
			s.lnsRouteWanted = map[string]ownedLNSRoute{}
		}
		s.lnsRouteWanted[lnsRouteKey(item)] = item
		out, showErr := s.Runner.Run(ctx, "ip", "-4", "route", "show", item.Destination)
		if showErr == nil && routeLineMatches(out, item) {
			continue
		}
		if _, err := s.Runner.Run(ctx, "ip", "route", "replace", item.Destination,
			"via", gateway, "dev", iface, "proto", fmt.Sprint(config.RouteProto)); err != nil {
			return fmt.Errorf("маршрут до концентратора %s: %w", ip, err)
		}
	}
	if !foundIPv4 {
		return fmt.Errorf("для концентратора %s не найден IPv4-адрес", w.Server)
	}
	return nil
}

func lnsRouteKey(item ownedLNSRoute) string {
	return item.Destination + "\x00" + item.Gateway + "\x00" + item.Interface
}

func (s *WAN) readOwnedLNSRoutes() ([]ownedLNSRoute, error) {
	if s.OwnedLNSRoutePath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(s.OwnedLNSRoutePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение списка маршрутов L2TP netOS: %w", err)
	}
	var items []ownedLNSRoute
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("чтение списка маршрутов L2TP netOS: %w", err)
	}
	return items, nil
}

func (s *WAN) writeOwnedLNSRoutes(items []ownedLNSRoute) error {
	if s.OwnedLNSRoutePath == "" {
		return nil
	}
	sort.Slice(items, func(i, j int) bool { return lnsRouteKey(items[i]) < lnsRouteKey(items[j]) })
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if _, err := system.WriteFileAtomicIfChanged(s.OwnedLNSRoutePath, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("запись списка маршрутов L2TP netOS: %w", err)
	}
	return nil
}

func (s *WAN) rememberLNSRoute(item ownedLNSRoute) error {
	previous, err := s.readOwnedLNSRoutes()
	if err != nil {
		return err
	}
	byKey := map[string]ownedLNSRoute{lnsRouteKey(item): item}
	for _, route := range previous {
		byKey[lnsRouteKey(route)] = route
	}
	combined := make([]ownedLNSRoute, 0, len(byKey))
	for _, route := range byKey {
		combined = append(combined, route)
	}
	return s.writeOwnedLNSRoutes(combined)
}

func (s *WAN) syncLNSRouteOwnership(ctx context.Context) error {
	previous, err := s.readOwnedLNSRoutes()
	if err != nil {
		return err
	}
	for _, item := range previous {
		if _, wanted := s.lnsRouteWanted[lnsRouteKey(item)]; wanted {
			continue
		}
		if _, err := s.Runner.Run(ctx, "ip", "-4", "route", "del", item.Destination,
			"via", item.Gateway, "dev", item.Interface, "proto", fmt.Sprint(config.RouteProto)); err != nil {
			out, showErr := s.Runner.Run(ctx, "ip", "-4", "route", "show", item.Destination)
			if showErr != nil || routeLineMatches(out, item) {
				return fmt.Errorf("удаление старого маршрута L2TP %s: %w", item.Destination, err)
			}
		}
	}
	wanted := make([]ownedLNSRoute, 0, len(s.lnsRouteWanted))
	for _, item := range s.lnsRouteWanted {
		wanted = append(wanted, item)
	}
	return s.writeOwnedLNSRoutes(wanted)
}

func routeLineMatches(out string, item ownedLNSRoute) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != item.Destination && fields[0] != strings.TrimSuffix(item.Destination, "/32")) {
			continue
		}
		via, dev := "", ""
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "via" {
				via = fields[i+1]
			}
			if fields[i] == "dev" {
				dev = fields[i+1]
			}
		}
		if via == item.Gateway && dev == item.Interface {
			return true
		}
	}
	return false
}

func (s *WAN) healthLNSRoutes(ctx context.Context, w config.WAN, iface string) error {
	owned, err := s.readOwnedLNSRoutes()
	if err != nil {
		return err
	}
	found := false
	for _, item := range owned {
		if item.Interface != iface {
			continue
		}
		found = true
		out, err := s.Runner.Run(ctx, "ip", "-4", "route", "show", item.Destination)
		if err != nil || !routeLineMatches(out, item) {
			return fmt.Errorf("аплинк %s: маршрут L2TP до %s через %s dev %s отсутствует", w.Name, item.Destination, item.Gateway, item.Interface)
		}
	}
	if !found {
		return fmt.Errorf("аплинк %s: не сохранён маршрут L2TP до концентратора %s", w.Name, w.Server)
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
	units, err := filepath.Glob(filepath.Join(systemdUnitDir, "netos-l2tp-*.service"))
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
		_, stopErr := s.Runner.Run(ctx, "systemctl", "disable", "--now", base)
		if s.unitActive(ctx, base) {
			if stopErr != nil {
				return fmt.Errorf("остановка %s: %w", base, stopErr)
			}
			return fmt.Errorf("служба %s осталась активной", base)
		}
		if linkExists(L2TPInterface(id)) {
			return fmt.Errorf("интерфейс %s остался после остановки %s", L2TPInterface(id), base)
		}
		for _, path := range []string{unitPath, l2tpConfPath(id), l2tpPPPPath(id)} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("удаление %s: %w", path, err)
			}
		}
		changed = true
	}
	for _, pattern := range []string{"l2tp-*.conf", "l2tp-*.ppp"} {
		paths, err := filepath.Glob(filepath.Join(pppoeConfDir, pattern))
		if err != nil {
			return err
		}
		for _, artifactPath := range paths {
			base := filepath.Base(artifactPath)
			id := strings.TrimPrefix(base, "l2tp-")
			id = strings.TrimSuffix(strings.TrimSuffix(id, ".conf"), ".ppp")
			if wanted[id] {
				continue
			}
			if err := os.Remove(artifactPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("удаление %s: %w", artifactPath, err)
			}
		}
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	return nil
}

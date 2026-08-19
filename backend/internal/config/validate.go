package config

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Problem — одна найденная проблема конфигурации. Path указывает на поле в
// JSON-документе, чтобы панель могла подсветить конкретный элемент формы.
type Problem struct {
	Path     string `json:"path"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // error | warning
}

func (p Problem) Error() string { return p.Path + ": " + p.Message }

type ValidationResult struct {
	Problems []Problem `json:"problems"`
}

func (r *ValidationResult) errf(path, format string, args ...any) {
	r.Problems = append(r.Problems, Problem{Path: path, Message: fmt.Sprintf(format, args...), Severity: "error"})
}

func (r *ValidationResult) warnf(path, format string, args ...any) {
	r.Problems = append(r.Problems, Problem{Path: path, Message: fmt.Sprintf(format, args...), Severity: "warning"})
}

func (r *ValidationResult) HasErrors() bool {
	for _, p := range r.Problems {
		if p.Severity == "error" {
			return true
		}
	}
	return false
}

// Validate проверяет конфигурацию целиком. Всё, что можно поймать до попытки
// применения, должно ловиться здесь: живой роутер — плохое место для
// выяснения, что две подсети пересекаются.
func (c *Config) Validate() *ValidationResult {
	r := &ValidationResult{}

	c.validateSystem(r)
	c.validateComponents(r)
	c.validateInterfaces(r)
	c.validateNetworks(r)
	c.validateWANs(r)
	c.validateRouting(r)
	c.validateFirewall(r)
	c.validateDHCP(r)
	c.validateDNS(r)
	c.validateChannels(r)
	c.validatePolicies(r)
	c.validateVPNServers(r)
	c.validateWiFi(r)

	return r
}

func (c *Config) validateSystem(r *ValidationResult) {
	if c.System.Hostname == "" {
		r.errf("system.hostname", "имя хоста не может быть пустым")
	}
	if p := c.System.Panel.Port; p < 1 || p > 65535 {
		r.errf("system.panel.port", "порт панели вне диапазона 1-65535")
	}
	if c.DNS.Enabled && c.System.Panel.Port == c.DNS.Port {
		r.errf("system.panel.port", "порт панели совпадает с портом DNS")
	}
	if c.System.Panel.CommitTimeout < 15 {
		r.warnf("system.panel.commit_timeout",
			"меньше 15 секунд может не хватить, чтобы подтвердить изменения")
	}
	switch c.System.NetworkBackend {
	case "netos", "ifupdown", "networkd":
	default:
		r.errf("system.network_backend", "неизвестный способ настройки сети %q", c.System.NetworkBackend)
	}
	if c.IPv6.Mode != "off" && c.IPv6.Mode != "passthrough" {
		r.errf("ipv6.mode", "неизвестный режим %q", c.IPv6.Mode)
	}
}

// validateComponents следит, чтобы выбранные службы были установлены. Без
// этого пользователь включит DHCP, а применение упадёт на отсутствующем пакете.
func (c *Config) validateComponents(r *ValidationResult) {
	for i, comp := range c.Components {
		if _, ok := ComponentByID(comp.ID); !ok {
			r.errf(fmt.Sprintf("components[%d].id", i), "неизвестный компонент %q", comp.ID)
		}
	}

	if c.DHCP.Enabled {
		if c.DHCP.Provider == "" {
			r.errf("dhcp.provider", "выдача адресов включена, но сервер DHCP не выбран")
		} else if !c.HasComponent(c.DHCP.Provider) {
			r.errf("dhcp.provider",
				"сервер DHCP %q не установлен — установите его в разделе «Компоненты»", c.DHCP.Provider)
		}
	}
	if c.DNS.Enabled {
		if c.DNS.Provider == "" {
			r.errf("dns.provider", "резолвер включён, но не выбран")
		} else if !c.HasComponent(c.DNS.Provider) {
			r.errf("dns.provider",
				"резолвер %q не установлен — установите его в разделе «Компоненты»", c.DNS.Provider)
		}
	}

	for i, w := range c.WANs {
		if !w.Enabled {
			continue
		}
		switch w.Proto {
		case "pppoe":
			if !c.HasComponent("pppoe") {
				r.errf(fmt.Sprintf("wans[%d].proto", i),
					"для PPPoE нужен компонент «PPPoE» — установите его в разделе «Компоненты»")
			}
		case "l2tp":
			if !c.HasComponent("l2tp") {
				r.errf(fmt.Sprintf("wans[%d].proto", i),
					"для L2TP нужен компонент «L2TP» — установите его в разделе «Компоненты»")
			}
		}
	}

	for i, radio := range c.WiFi {
		if radio.Enabled && !c.HasComponent("hostapd") {
			r.errf(fmt.Sprintf("wifi[%d]", i),
				"для точки доступа нужен компонент «Точка доступа Wi-Fi»")
		}
	}
}

func (c *Config) validateInterfaces(r *ValidationResult) {
	names := map[string]bool{}
	ids := map[string]bool{}
	for i, iface := range c.Interfaces {
		path := fmt.Sprintf("interfaces[%d]", i)
		if iface.ID == "" {
			r.errf(path+".id", "пустой идентификатор")
		} else if ids[iface.ID] {
			r.errf(path+".id", "дубликат идентификатора %q", iface.ID)
		}
		ids[iface.ID] = true

		if iface.Name == "" {
			r.errf(path+".name", "пустое имя интерфейса")
		} else if names[iface.Name] {
			r.errf(path+".name", "интерфейс %q объявлен дважды", iface.Name)
		}
		names[iface.Name] = true

		switch iface.Type {
		case "physical":
		case "bridge":
		case "bond":
			if len(iface.Members) < 2 {
				r.errf(path+".members", "агрегация требует минимум два порта")
			}
		case "vlan":
			if iface.Parent == "" {
				r.errf(path+".parent", "не указан родительский интерфейс")
			}
			if iface.VLANID < 1 || iface.VLANID > 4094 {
				r.errf(path+".vlan_id", "VLAN ID должен быть в диапазоне 1-4094")
			}
		default:
			r.errf(path+".type", "неизвестный тип интерфейса %q", iface.Type)
		}

		if iface.MTU != 0 && (iface.MTU < 576 || iface.MTU > 9216) {
			r.errf(path+".mtu", "MTU вне разумного диапазона 576-9216")
		}
		if iface.MAC != "" {
			if _, err := net.ParseMAC(iface.MAC); err != nil {
				r.errf(path+".mac", "некорректный MAC-адрес")
			}
		}
	}

	for i, iface := range c.Interfaces {
		path := fmt.Sprintf("interfaces[%d]", i)
		if iface.Type == "vlan" && iface.Parent != "" && !names[iface.Parent] {
			r.warnf(path+".parent", "родительский интерфейс %q не объявлен", iface.Parent)
		}
		for _, m := range iface.Members {
			if !names[m] {
				r.warnf(path+".members", "порт %q не объявлен в конфигурации", m)
			}
		}
	}
}

func (c *Config) validateNetworks(r *ValidationResult) {
	ifaceIDs := c.interfaceIDs()
	zones := c.zoneNames()
	channels := c.channelIDs()

	type seg struct {
		name   string
		prefix netip.Prefix
	}
	var segs []seg

	for i, n := range c.Networks {
		path := fmt.Sprintf("networks[%d]", i)
		if n.Name == "" {
			r.errf(path+".name", "пустое имя сегмента")
		}
		if !ifaceIDs[n.Interface] {
			r.errf(path+".interface", "сегмент ссылается на несуществующий интерфейс %q", n.Interface)
		}
		if !zones[n.Zone] {
			r.errf(path+".zone", "неизвестная зона файрволла %q", n.Zone)
		}
		if n.DefaultChannel != "" && !channels[n.DefaultChannel] {
			r.errf(path+".default_channel", "неизвестный канал %q", n.DefaultChannel)
		}

		prefix, err := netip.ParsePrefix(n.RouterAddress)
		if err != nil {
			r.errf(path+".router_address",
				"нужен адрес роутера вместе с маской, например 192.168.10.1/24")
			continue
		}
		if !prefix.Addr().Is4() {
			r.errf(path+".router_address", "поддерживаются только адреса IPv4")
			continue
		}
		if prefix.Addr() == prefix.Masked().Addr() {
			r.errf(path+".router_address",
				"указан адрес сети, а не адрес роутера в ней — обычно это первый адрес, например 192.168.10.1/24")
		}

		for _, s := range segs {
			if s.prefix.Overlaps(prefix) {
				r.errf(path+".router_address", "подсеть пересекается с сегментом %q (%s)", s.name, s.prefix)
			}
		}
		segs = append(segs, seg{name: n.Name, prefix: prefix})

		c.validatePool(r, path, n, prefix)
	}
}

func (c *Config) validatePool(r *ValidationResult, path string, n Network, prefix netip.Prefix) {
	p := n.DHCPPool
	if !p.Enabled {
		return
	}
	if !c.DHCP.Enabled {
		r.warnf(path+".dhcp_pool.enabled",
			"пул задан, но сервер DHCP выключен — адреса выдаваться не будут")
	}
	start, errS := netip.ParseAddr(p.Start)
	end, errE := netip.ParseAddr(p.End)
	if errS != nil {
		r.errf(path+".dhcp_pool.start", "некорректный адрес начала пула")
		return
	}
	if errE != nil {
		r.errf(path+".dhcp_pool.end", "некорректный адрес конца пула")
		return
	}
	if !prefix.Contains(start) {
		r.errf(path+".dhcp_pool.start", "начало пула вне подсети %s", prefix)
	}
	if !prefix.Contains(end) {
		r.errf(path+".dhcp_pool.end", "конец пула вне подсети %s", prefix)
	}
	if start.Compare(end) > 0 {
		r.errf(path+".dhcp_pool", "начало пула больше конца")
	}
	if prefix.Addr() == start || prefix.Addr() == end {
		r.errf(path+".dhcp_pool", "пул включает адрес самого роутера")
	}
	if p.LeaseTime < 120 {
		r.warnf(path+".dhcp_pool.lease_time", "слишком короткое время аренды")
	}
}

func (c *Config) validateWANs(r *ValidationResult) {
	ifaceIDs := c.interfaceIDs()
	enabled := 0
	// Метрика — единственное, чем аплинки упорядочены между собой: она решает,
	// какой из них основной. Две одинаковые означают, что выбор остаётся за
	// ядром, а переключение при отказе становится непредсказуемым.
	metricOwner := map[int]string{}
	claimMetric := func(path string, metric int, owner string) {
		if previous, taken := metricOwner[metric]; taken {
			r.errf(path+".metric",
				"приоритет %d уже занят (%s): по нему выбирается основной аплинк, и он должен быть уникальным",
				metric, previous)
			return
		}
		metricOwner[metric] = owner
	}

	for i, w := range c.WANs {
		path := fmt.Sprintf("wans[%d]", i)
		if !ifaceIDs[w.Interface] {
			r.errf(path+".interface", "аплинк ссылается на несуществующий интерфейс %q", w.Interface)
		}
		if w.Enabled {
			enabled++
			if w.Metric <= 0 {
				r.errf(path+".metric", "приоритет должен быть положительным числом")
			} else {
				claimMetric(path, w.Metric, w.Name)
				if w.Proto == "l2tp" {
					// Сеть провайдера под туннелем получает свой маршрут по
					// умолчанию с худшей метрикой, и он тоже участвует в общем
					// порядке.
					claimMetric(path, w.Metric+10, w.Name+" (сеть провайдера)")
				}
			}
		}
		switch w.Proto {
		case "dhcp":
		case "static":
			prefix, prefixErr := netip.ParsePrefix(w.Address)
			if prefixErr != nil {
				r.errf(path+".address", "адрес должен быть с маской, например 203.0.113.5/24")
			}
			gw, gwErr := netip.ParseAddr(w.Gateway)
			if gwErr != nil {
				r.errf(path+".gateway", "некорректный адрес шлюза")
			}
			// Шлюз вне подсети интерфейса ядру недостижим: ip route отвечает
			// «Nexthop has invalid gateway», применение падает и откатывается.
			// Откат спасает связность, но администратор узнаёт о промахе уже
			// после того, как аплинк на секунду перестроили. Предупреждаем до
			// применения — ошибкой это делать нельзя, бывают точка-точка и
			// шлюз за onlink-маршрутом.
			if prefixErr == nil && gwErr == nil && !prefix.Contains(gw) {
				r.warnf(path+".gateway",
					"шлюз %s вне подсети %s: ядро примет такой маршрут только через onlink",
					w.Gateway, w.Address)
			}
		case "pppoe":
			if w.Username == "" {
				r.errf(path+".username", "для PPPoE нужен логин")
			}
			// Интерфейс сессии называется ppp-<id>, и на него ссылаются зоны
			// файрволла. Ядро обрежет слишком длинное имя, и правила уйдут в
			// пустоту — ловим это до применения.
			if n := len("ppp-" + w.ID); n > maxInterfaceName {
				r.errf(path+".id",
					"идентификатор слишком длинный: имя интерфейса ppp-%s не помещается в %d символов",
					w.ID, maxInterfaceName)
			}
		case "l2tp":
			if w.Server == "" {
				r.errf(path+".server", "укажите адрес сервера L2TP")
			}
			if w.Username == "" {
				r.errf(path+".username", "для L2TP нужен логин")
			}
			switch w.Underlay {
			case "", "dhcp":
			case "static":
				// Туннель поднимается поверх адреса в сети провайдера. Без него
				// не найти ни концентратор, ни маршрут до него.
				if _, err := netip.ParsePrefix(w.Address); err != nil {
					r.errf(path+".address",
						"для статического адреса под туннелем нужен адрес с маской, например 10.0.0.5/24")
				}
				if _, err := netip.ParseAddr(w.Gateway); err != nil {
					r.errf(path+".gateway", "укажите шлюз сети провайдера")
				}
			default:
				r.errf(path+".underlay", "неизвестный способ получения адреса %q", w.Underlay)
			}
			// Интерфейс сессии называется ppp-<id>, как и у PPPoE.
			if n := len("ppp-" + w.ID); n > maxInterfaceName {
				r.errf(path+".id",
					"идентификатор слишком длинный: имя интерфейса ppp-%s не помещается в %d символов",
					w.ID, maxInterfaceName)
			}
		default:
			r.errf(path+".proto", "неизвестный тип подключения %q", w.Proto)
		}
	}
	if enabled == 0 && len(c.Networks) > 0 {
		r.warnf("wans", "нет ни одного включённого аплинка — выхода в интернет не будет")
	}
	if enabled > 1 && !c.MultiWAN.Enabled {
		r.warnf("multiwan.enabled",
			"включено несколько аплинков, но Multi-WAN выключен — использоваться будет только один")
	}
}

func (c *Config) validateRouting(r *ValidationResult) {
	tables := map[string]bool{"main": true, "default": true, "local": true}
	numbers := map[int]string{}

	for i, t := range c.Routing.Tables {
		path := fmt.Sprintf("routing.tables[%d]", i)
		if t.Name == "" {
			r.errf(path+".name", "пустое имя таблицы")
		}
		if tables[t.Name] {
			r.errf(path+".name", "таблица %q уже существует", t.Name)
		}
		tables[t.Name] = true

		if t.Number < 1 || t.Number > 252 {
			r.errf(path+".number", "номер таблицы должен быть в диапазоне 1-252")
		}
		if prev, ok := numbers[t.Number]; ok {
			r.errf(path+".number", "номер %d уже занят таблицей %q", t.Number, prev)
		}
		numbers[t.Number] = t.Name
	}

	for i, route := range c.Routing.Static {
		path := fmt.Sprintf("routing.static[%d]", i)
		if route.Destination != "default" {
			if _, err := netip.ParsePrefix(route.Destination); err != nil {
				if _, err := netip.ParseAddr(route.Destination); err != nil {
					r.errf(path+".destination", "ожидается подсеть, адрес или слово default")
				}
			}
		}
		if route.Gateway != "" {
			if _, err := netip.ParseAddr(route.Gateway); err != nil {
				r.errf(path+".gateway", "некорректный адрес шлюза")
			}
		}
		if route.Gateway == "" && route.Interface == "" && route.Type == "" {
			r.errf(path, "укажите шлюз, интерфейс или тип маршрута")
		}
		if route.Table != "" && !tables[route.Table] {
			r.errf(path+".table", "неизвестная таблица %q", route.Table)
		}
	}

	priorities := map[int]string{}
	for i, rule := range c.Routing.Rules {
		path := fmt.Sprintf("routing.rules[%d]", i)
		if rule.Table == "" {
			r.errf(path+".table", "не указана таблица")
		} else if !tables[rule.Table] {
			r.errf(path+".table", "неизвестная таблица %q", rule.Table)
		}
		if rule.Priority < 20000 || rule.Priority > 29999 {
			r.errf(path+".priority",
				"приоритет должен быть в диапазоне 20000-29999: этот диапазон netOS считает своим")
		}
		if prev, ok := priorities[rule.Priority]; ok {
			r.warnf(path+".priority", "приоритет %d уже занят правилом %q", rule.Priority, prev)
		}
		priorities[rule.Priority] = rule.Name
		validateCIDR(r, path+".from", rule.From)
		validateCIDR(r, path+".to", rule.To)
	}
}

func (c *Config) validateFirewall(r *ValidationResult) {
	zones := c.zoneNames()
	policies := map[string]bool{"accept": true, "drop": true, "reject": true}

	for i, z := range c.Firewall.Zones {
		path := fmt.Sprintf("firewall.zones[%d]", i)
		if !policies[z.Policy] {
			r.errf(path+".policy", "недопустимая политика %q", z.Policy)
		}
	}
	if !policies[c.Firewall.OutputPolicy] {
		r.errf("firewall.output_policy", "недопустимая политика %q", c.Firewall.OutputPolicy)
	}
	if c.Firewall.OutputPolicy != "accept" {
		r.warnf("firewall.output_policy",
			"исходящий трафик самого роутера ограничен: проверьте, что разрешены обновления, DNS и подключения к VPN-серверам")
	}

	if !c.Firewall.Enabled {
		r.warnf("firewall.enabled",
			"файрволл выключен: роутер пропускает весь трафик без фильтрации")
	}

	ids := map[string]bool{}
	for i, rule := range c.Firewall.Rules {
		path := fmt.Sprintf("firewall.rules[%d]", i)
		if ids[rule.ID] {
			r.errf(path+".id", "дубликат идентификатора правила %q", rule.ID)
		}
		ids[rule.ID] = true

		switch rule.Action {
		case "accept", "drop", "reject", "continue":
		default:
			r.errf(path+".action", "недопустимое действие %q", rule.Action)
		}
		switch rule.Flow {
		case "in", "out", "forward":
		default:
			r.errf(path+".flow", "недопустимое направление %q", rule.Flow)
		}
		if rule.Zone != "global" && !zones[rule.Zone] {
			r.errf(path+".zone", "неизвестная зона %q", rule.Zone)
		}
		if rule.DstZone != "" {
			if !zones[rule.DstZone] {
				r.errf(path+".dst_zone", "неизвестная зона назначения %q", rule.DstZone)
			}
			if rule.Flow != "forward" {
				r.errf(path+".dst_zone",
					"зона назначения осмысленна только для форварда: у входа и выхода второй зоны нет")
			}
		}
		validateCIDR(r, path+".src_ip", rule.SrcIP)
		validateCIDR(r, path+".dst_ip", rule.DstIP)
		validatePortSpec(r, path+".src_port", rule.SrcPort)
		validatePortSpec(r, path+".dst_port", rule.DstPort)
		if rule.SrcMAC != "" {
			if _, err := net.ParseMAC(rule.SrcMAC); err != nil {
				r.errf(path+".src_mac", "некорректный MAC-адрес")
			}
		}
		if (rule.DstPort != "" || rule.SrcPort != "") && rule.Protocol != "tcp" && rule.Protocol != "udp" {
			r.errf(path+".protocol", "для правила с портами нужно выбрать протокол TCP или UDP")
		}
	}

	c.validateAccessRules(r)

	ifaceNames := map[string]bool{}
	for _, i := range c.Interfaces {
		ifaceNames[i.Name] = true
	}

	for i, n := range c.Firewall.NAT {
		path := fmt.Sprintf("firewall.nat[%d]", i)
		switch n.Direction {
		case "source":
			if n.Interface == "" {
				r.errf(path+".interface", "не выбран интерфейс, на выходе через который подменять адрес")
			} else if !ifaceNames[n.Interface] {
				r.warnf(path+".interface", "интерфейс %q не описан в конфигурации", n.Interface)
			}
			validateCIDR(r, path+".source", n.Source)
			if n.ToSource != "" {
				if _, err := netip.ParseAddr(n.ToSource); err != nil {
					r.errf(path+".to_source", "некорректный адрес подмены")
				}
			}
		case "destination":
			if n.Protocol != "tcp" && n.Protocol != "udp" && n.Protocol != "tcpudp" {
				r.errf(path+".protocol", "протокол должен быть tcp, udp или tcpudp")
			}
			validatePortSpec(r, path+".ext_port", n.ExtPort)
			validatePortSpec(r, path+".dest_port", n.DestPort)
			if _, err := netip.ParseAddr(n.DestIP); err != nil {
				r.errf(path+".dest_ip", "некорректный адрес назначения")
			}
			validateCIDR(r, path+".allow_from", n.AllowFrom)
			if n.Enabled && n.ExtPort == fmt.Sprint(c.System.Panel.Port) {
				r.warnf(path, "внешний порт совпадает с портом веб-панели: панель станет недоступна")
			}
			if n.Enabled && n.ExtPort == "22" {
				r.warnf(path, "внешний порт 22 занят SSH: доступ по SSH перестанет работать")
			}
		default:
			r.errf(path+".direction", "неизвестное направление трансляции %q", n.Direction)
		}
	}

	// Клиенты не выйдут в интернет без подмены адреса, и это стоит сказать
	// заранее, а не оставлять администратора гадать.
	if c.Firewall.Enabled && len(c.Networks) > 0 {
		hasSNAT := false
		for _, n := range c.Firewall.NAT {
			if n.Enabled && n.Direction == "source" {
				hasSNAT = true
			}
		}
		if !hasSNAT {
			r.warnf("firewall.nat",
				"нет ни одного правила подмены адреса: клиенты локальной сети не смогут выйти в интернет")
		}
	}
}

// reachableForManagement проверяет, остаётся ли у администратора хоть один
// способ попасть на роутер по сети.
//
// Это последний рубеж перед потерей машины. Роутер с политикой DROP и без
// единого разрешающего правила отвечать перестаёт совсем: ни SSH, ни панель,
// ни пинг. Восстановить его можно только с физической или аварийной консоли,
// а у виртуальной машины в чужом дата-центре её может не быть вовсе.
func (c *Config) reachableForManagement() bool {
	// Зона с политикой accept и хотя бы одним живым интерфейсом уже означает
	// доступность: правило по умолчанию пропустит подключение.
	for _, z := range c.Firewall.Zones {
		if z.Policy == "accept" && c.zoneHasInterfaces(z.Name) {
			return true
		}
	}

	for _, r := range c.Firewall.Rules {
		if c.ruleGrantsManagement(r) {
			return true
		}
	}
	return false
}

// ruleGrantsManagement сообщает, может ли по этому правилу пройти живое
// управляющее подключение.
//
// Важно не засчитывать лишнего: разрешённый DHCP на UDP 67 или пинг ничем не
// помогут администратору, оставшемуся без доступа, а ложное «всё в порядке»
// от защиты хуже её отсутствия.
func (c *Config) ruleGrantsManagement(r FirewallRule) bool {
	if !r.Enabled || r.Action != "accept" {
		return false
	}
	if r.Flow != "in" {
		return false
	}
	// Ответы на уже установленные соединения новых подключений не пропускают.
	if strings.Contains(r.ConnState, "established") {
		return false
	}
	// Петля работает только внутри самой машины.
	if r.Interface == "lo" {
		return false
	}
	// Правило в зоне без интерфейсов не превращается ни в одну строку правил.
	if r.Zone != "global" && !c.zoneHasInterfaces(r.Zone) {
		return false
	}

	switch r.Protocol {
	case "", "any":
		// Ограничения по протоколу нет — пройдёт в том числе и SSH.
		return true
	case "tcp":
		if r.DstPort == "" {
			return true
		}
		// Управление возможно только через порт SSH или порт панели.
		return portSpecContains(r.DstPort, 22) ||
			portSpecContains(r.DstPort, c.System.Panel.Port)
	}
	// UDP и ICMP интерактивного доступа не дают.
	return false
}

// zoneHasInterfaces сообщает, есть ли в зоне хоть один действующий интерфейс.
func (c *Config) zoneHasInterfaces(zone string) bool {
	for _, n := range c.Networks {
		if n.Enabled && n.Zone == zone {
			return true
		}
	}
	if zone == "wan" {
		for _, w := range c.WANs {
			if w.Enabled {
				return true
			}
		}
	}
	if zone == "vpn" {
		for _, ch := range c.Channels {
			if ch.Enabled && ch.Type != "direct" {
				return true
			}
		}
		for _, s := range c.VPNServers {
			if s.Enabled {
				return true
			}
		}
	}
	return false
}

// portSpecContains разбирает спецификацию вида "22", "80,443" или "8000-9000".
func portSpecContains(spec string, port int) bool {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		from, err := parsePort(lo)
		if err != nil {
			continue
		}
		if !isRange {
			if from == port {
				return true
			}
			continue
		}
		to, err := parsePort(hi)
		if err != nil {
			continue
		}
		if port >= from && port <= to {
			return true
		}
	}
	return false
}

func parsePort(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("пустой порт")
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("не число")
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

// validateAccessRules следит за правилами, от которых зависит доступ к самому
// роутеру. Запрещать администратору их выключать мы не вправе, но обязаны
// сказать вслух, что он делает.
func (c *Config) validateAccessRules(r *ValidationResult) {
	if !c.Firewall.Enabled {
		return
	}
	if !c.reachableForManagement() {
		r.errf("firewall.rules",
			"конфигурация не оставляет ни одного способа подключиться к роутеру: политика зон запрещает входящие соединения, и нет ни одного разрешающего правила. Применение отрезало бы доступ к машине без возможности восстановить его по сети")
	}

	byID := map[string]FirewallRule{}
	for _, rule := range c.Firewall.Rules {
		byID[rule.ID] = rule
	}

	if rule, ok := byID[RuleSSH]; ok && !rule.Enabled {
		r.warnf("firewall.rules",
			"правило доступа по SSH выключено: попасть на роутер можно будет только через панель или консоль")
	}
	if rule, ok := byID[RulePanel]; ok && !rule.Enabled {
		r.warnf("firewall.rules",
			"правило доступа к веб-панели выключено: после применения панель перестанет открываться")
	}
	if rule, ok := byID[RuleEstablishedIn]; ok && !rule.Enabled {
		r.errf("firewall.rules",
			"правило про установленные соединения выключено: ответы на исходящие запросы перестанут приходить, роутер потеряет связь")
	}
	if rule, ok := byID[RuleLANOut]; ok && !rule.Enabled {
		r.warnf("firewall.rules",
			"выход из локальной сети в интернет запрещён: у клиентов не будет доступа наружу")
	}
}

func (c *Config) validateDHCP(r *ValidationResult) {
	if c.DHCP.Provider != "" {
		switch c.DHCP.Provider {
		case "dnsmasq", "isc-dhcp-server", "kea":
		default:
			r.errf("dhcp.provider", "неизвестный сервер DHCP %q", c.DHCP.Provider)
		}
	}

	networks := c.networkIDs()
	seenMAC := map[string]bool{}
	seenIP := map[string]bool{}

	for i, res := range c.DHCP.Reservations {
		path := fmt.Sprintf("dhcp.reservations[%d]", i)
		mac, err := net.ParseMAC(res.MAC)
		if err != nil {
			r.errf(path+".mac", "некорректный MAC-адрес")
		} else {
			key := strings.ToLower(mac.String())
			if seenMAC[key] {
				r.errf(path+".mac", "для этого MAC уже есть привязка")
			}
			seenMAC[key] = true
		}
		addr, err := netip.ParseAddr(res.IP)
		if err != nil {
			r.errf(path+".ip", "некорректный IP-адрес")
		} else {
			if seenIP[res.IP] {
				r.errf(path+".ip", "адрес %s уже закреплён за другим устройством", res.IP)
			}
			seenIP[res.IP] = true
			if !c.addressInNetwork(res.Network, addr) {
				r.errf(path+".ip", "адрес не принадлежит подсети выбранного сегмента")
			}
		}
		if !networks[res.Network] {
			r.errf(path+".network", "неизвестный сегмент %q", res.Network)
		}
	}
}

func (c *Config) validateDNS(r *ValidationResult) {
	if c.DNS.Provider != "" {
		switch c.DNS.Provider {
		case "dnsmasq", "unbound", "dnsproxy", "adguardhome":
		default:
			r.errf("dns.provider", "неизвестный резолвер %q", c.DNS.Provider)
		}
	}

	channels := c.channelIDs()
	upstreams := map[string]bool{}
	secure := 0

	for i, u := range c.DNS.Upstreams {
		path := fmt.Sprintf("dns.upstreams[%d]", i)
		upstreams[u.ID] = true
		switch u.Type {
		case "plain":
		case "dot", "doh", "doq":
			if u.Enabled {
				secure++
			}
			if c.DNS.Enabled && c.DNS.Provider == "dnsmasq" {
				r.errf(path+".type",
					"dnsmasq не умеет %s — выберите unbound, dnsproxy или AdGuard Home",
					strings.ToUpper(u.Type))
			}
			if u.Type != "dot" && c.DNS.Enabled && c.DNS.Provider == "unbound" {
				r.errf(path+".type", "unbound поддерживает только DoT")
			}
		default:
			r.errf(path+".type", "неизвестный тип апстрима %q", u.Type)
		}
		if u.Address == "" {
			r.errf(path+".address", "пустой адрес апстрима")
		}
		if u.Channel != "" && !channels[u.Channel] {
			r.errf(path+".channel", "неизвестный канал %q", u.Channel)
		}
	}

	if secure > 0 && len(c.DNS.Bootstrap) == 0 {
		r.warnf("dns.bootstrap",
			"для шифрованного DNS нужен обычный резолвер, чтобы разрешить имя самого сервера")
	}

	// unbound не умеет вырезать AAAA из ответов. Молчать об этом нельзя:
	// администратор видит в настройках включённый фильтр и считает, что он
	// работает, — выбрав unbound, он получит AAAA в ответах.
	if c.DNS.Enabled && c.DNS.Provider == "unbound" && c.IPv6.FilterAAAA {
		r.warnf("ipv6.filter_aaaa",
			"unbound не фильтрует AAAA — записи дойдут до клиентов; вырезать их умеют dnsmasq, dnsproxy и AdGuard Home")
	}

	for i, rule := range c.DNS.SplitRules {
		path := fmt.Sprintf("dns.split_rules[%d]", i)
		if len(rule.Domains) == 0 {
			r.errf(path+".domains", "правило без доменов")
		}
		if rule.Upstream != "" && !upstreams[rule.Upstream] {
			r.errf(path+".upstream", "неизвестный апстрим %q", rule.Upstream)
		}
		if rule.Channel != "" && !channels[rule.Channel] {
			r.errf(path+".channel", "неизвестный канал %q", rule.Channel)
		}
	}
}

func (c *Config) validateChannels(r *ValidationResult) {
	ids := map[string]bool{}
	indexes := map[int]string{}
	for i, ch := range c.Channels {
		path := fmt.Sprintf("channels[%d]", i)
		if ids[ch.ID] {
			r.errf(path+".id", "дубликат идентификатора канала %q", ch.ID)
		}
		ids[ch.ID] = true
		if prev, ok := indexes[ch.Index]; ok {
			r.errf(path+".index", "индекс %d уже занят каналом %q", ch.Index, prev)
		}
		indexes[ch.Index] = ch.ID

		switch ch.Type {
		case "direct", "wireguard", "xray", "openconnect", "l2tp", "ikev2":
		default:
			r.errf(path+".type", "неизвестный тип канала %q", ch.Type)
		}
		switch ch.Mode {
		case "tun", "tproxy", "socks":
		default:
			r.errf(path+".mode", "неизвестный режим перехвата %q", ch.Mode)
		}
		switch ch.FailMode {
		case "block", "fallback", "direct":
		default:
			r.errf(path+".fail_mode", "неизвестное поведение при отказе %q", ch.FailMode)
		}
		if ch.FailMode == "fallback" {
			if ch.Fallback == "" {
				r.errf(path+".fallback", "не выбран запасной канал")
			} else if ch.Fallback == ch.ID {
				r.errf(path+".fallback", "канал не может быть запасным сам себе")
			}
		}
	}

	byID := map[string]Channel{}
	for _, ch := range c.Channels {
		byID[ch.ID] = ch
	}
	for _, ch := range c.Channels {
		seen := map[string]bool{ch.ID: true}
		cur := ch
		for cur.FailMode == "fallback" && cur.Fallback != "" {
			next, ok := byID[cur.Fallback]
			if !ok {
				r.errf("channels", "канал %q ссылается на несуществующий запасной %q", cur.ID, cur.Fallback)
				break
			}
			if seen[next.ID] {
				r.errf("channels", "цикл в цепочке запасных каналов, начиная с %q", ch.ID)
				break
			}
			seen[next.ID] = true
			cur = next
		}
	}
}

func (c *Config) validatePolicies(r *ValidationResult) {
	channels := c.channelIDs()
	networks := c.networkIDs()
	servers := map[string]bool{}
	for _, s := range c.VPNServers {
		servers[s.ID] = true
	}

	for i, p := range c.Policies {
		path := fmt.Sprintf("policies[%d]", i)
		if !channels[p.Channel] {
			r.errf(path+".channel", "политика ссылается на несуществующий канал %q", p.Channel)
		}
		if p.Network != "" && !networks[p.Network] {
			r.errf(path+".network", "неизвестный сегмент %q", p.Network)
		}
		if p.VPNServer != "" && !servers[p.VPNServer] {
			r.errf(path+".vpn_server", "неизвестный VPN-сервер %q", p.VPNServer)
		}
		validateCIDR(r, path+".src_ip", p.SrcIP)
		validateCIDR(r, path+".dst_ip", p.DstIP)
		validatePortSpec(r, path+".dst_port", p.DstPort)
		if p.SrcMAC != "" {
			if _, err := net.ParseMAC(p.SrcMAC); err != nil {
				r.errf(path+".src_mac", "некорректный MAC-адрес")
			}
		}
		if p.SrcIP == "" && p.SrcMAC == "" && p.Network == "" && p.VPNServer == "" &&
			p.DstIP == "" && p.DstPort == "" && len(p.Domains) == 0 {
			r.warnf(path, "политика без единого условия перехватит весь трафик")
		}
	}
}

func (c *Config) validateVPNServers(r *ValidationResult) {
	channels := c.channelIDs()
	ports := map[int]string{}
	for i, s := range c.VPNServers {
		path := fmt.Sprintf("vpn_servers[%d]", i)
		switch s.Type {
		case "wireguard", "ikev2", "ocserv", "xray":
		default:
			r.errf(path+".type", "неизвестный тип VPN-сервера %q", s.Type)
		}
		subnet, err := netip.ParsePrefix(s.Subnet)
		if err != nil {
			r.errf(path+".subnet", "подсеть должна быть в формате 10.9.0.1/24")
		}
		if s.Enabled && s.Port != 0 {
			if prev, ok := ports[s.Port]; ok {
				r.errf(path+".port", "порт %d уже занят сервером %q", s.Port, prev)
			}
			ports[s.Port] = s.Name
			if s.Port == c.System.Panel.Port {
				r.errf(path+".port", "порт совпадает с портом веб-панели")
			}
		}
		if s.DefaultChannel != "" && !channels[s.DefaultChannel] {
			r.errf(path+".default_channel", "неизвестный канал %q", s.DefaultChannel)
		}

		seenAddr := map[string]bool{}
		for j, peer := range s.Peers {
			ppath := fmt.Sprintf("%s.peers[%d]", path, j)
			addr, err := netip.ParseAddr(peer.Address)
			if err != nil {
				r.errf(ppath+".address", "некорректный адрес")
				continue
			}
			if subnet.IsValid() && !subnet.Contains(addr) {
				r.errf(ppath+".address", "адрес вне подсети сервера %s", s.Subnet)
			}
			if seenAddr[peer.Address] {
				r.errf(ppath+".address", "адрес %s уже назначен другому клиенту", peer.Address)
			}
			seenAddr[peer.Address] = true
			if peer.Channel != "" && !channels[peer.Channel] {
				r.errf(ppath+".channel", "неизвестный канал %q", peer.Channel)
			}
		}
	}
}

func (c *Config) validateWiFi(r *ValidationResult) {
	networks := c.networkIDs()
	for i, radio := range c.WiFi {
		path := fmt.Sprintf("wifi[%d]", i)
		if radio.Device == "" {
			r.errf(path+".device", "не выбрано радиоустройство")
		}
		if radio.Country == "" {
			r.warnf(path+".country", "не задан код страны — часть каналов будет недоступна")
		}
		for j, s := range radio.SSIDs {
			spath := fmt.Sprintf("%s.ssids[%d]", path, j)
			if s.SSID == "" {
				r.errf(spath+".ssid", "пустое имя сети")
			}
			if len(s.SSID) > 32 {
				r.errf(spath+".ssid", "имя сети длиннее 32 байт")
			}
			if !networks[s.Network] {
				r.errf(spath+".network", "неизвестный сегмент %q", s.Network)
			}
			switch s.Security {
			case "open":
				r.warnf(spath+".security", "открытая сеть без шифрования")
			case "wpa2", "wpa3", "wpa2/wpa3":
				if len(s.Password) < 8 {
					r.errf(spath+".password", "пароль короче 8 символов")
				}
			default:
				r.errf(spath+".security", "неизвестный режим безопасности %q", s.Security)
			}
		}
	}
}

// --- вспомогательное ---

func (c *Config) interfaceIDs() map[string]bool {
	m := map[string]bool{}
	for _, i := range c.Interfaces {
		m[i.ID] = true
	}
	return m
}

func (c *Config) networkIDs() map[string]bool {
	m := map[string]bool{}
	for _, n := range c.Networks {
		m[n.ID] = true
	}
	return m
}

func (c *Config) channelIDs() map[string]bool {
	m := map[string]bool{}
	for _, ch := range c.Channels {
		m[ch.ID] = true
	}
	return m
}

func (c *Config) zoneNames() map[string]bool {
	m := map[string]bool{}
	for _, z := range c.Firewall.Zones {
		m[z.Name] = true
	}
	return m
}

func (c *Config) addressInNetwork(networkID string, addr netip.Addr) bool {
	for _, n := range c.Networks {
		if n.ID != networkID {
			continue
		}
		prefix, err := netip.ParsePrefix(n.RouterAddress)
		if err != nil {
			return false
		}
		return prefix.Contains(addr)
	}
	return false
}

func validateCIDR(r *ValidationResult, path, value string) {
	if value == "" {
		return
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return
	}
	r.errf(path, "ожидается адрес или подсеть, получено %q", value)
}

func validatePortSpec(r *ValidationResult, path, value string) {
	if value == "" {
		return
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		if !inPortRange(lo) || (isRange && !inPortRange(hi)) {
			r.errf(path, "некорректная спецификация порта %q", value)
			return
		}
	}
}

func inPortRange(s string) bool {
	if s == "" {
		return false
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
		n = n*10 + int(ch-'0')
		if n > 65535 {
			return false
		}
	}
	return n >= 1
}

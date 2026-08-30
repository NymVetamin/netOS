package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
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
	c.validateClients(r)
	c.validateChannels(r)
	c.validatePolicies(r)
	c.validateVPNServers(r)
	c.validateWiFi(r)

	return r
}

func (c *Config) validateClients(r *ValidationResult) {
	ids := map[string]int{}
	macs := map[string]int{}
	channels := c.usableChannelIDs()
	networks := c.networkIDs()
	blocked := 0

	for i, client := range c.Clients {
		path := fmt.Sprintf("clients[%d]", i)
		if client.ID == "" {
			r.errf(path+".id", "пустой идентификатор клиента")
		} else if prev, ok := ids[client.ID]; ok {
			r.errf(path+".id", "идентификатор уже занят клиентом clients[%d]", prev)
		} else {
			ids[client.ID] = i
		}

		hw, err := net.ParseMAC(client.MAC)
		if err != nil || len(hw) != 6 {
			r.errf(path+".mac", "некорректный MAC-адрес")
		} else {
			mac := strings.ToLower(hw.String())
			if prev, ok := macs[mac]; ok {
				r.errf(path+".mac", "MAC-адрес уже указан у клиента clients[%d]", prev)
			} else {
				macs[mac] = i
			}
		}

		if client.Network != "" && !networks[client.Network] {
			r.errf(path+".network", "неизвестный сегмент %q", client.Network)
		}
		if client.Channel != "" && !channels[client.Channel] {
			r.errf(path+".channel", "канал %q не существует или выключен", client.Channel)
		}
		if client.DownKbit < 0 {
			r.errf(path+".down_kbit", "скорость не может быть отрицательной")
		}
		if client.UpKbit < 0 {
			r.errf(path+".up_kbit", "скорость не может быть отрицательной")
		}
		if client.Blocked {
			blocked++
		}
	}

	if blocked > 0 && !c.Firewall.Enabled {
		r.warnf("clients", "файрволл выключен: блокировку %d клиент(ов) можно обойти статическим IP", blocked)
	}
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
	switch c.System.Panel.TLS.Mode {
	case "selfsigned":
	case "custom":
		if c.System.Panel.TLS.CertFile == "" || c.System.Panel.TLS.KeyFile == "" {
			r.errf("system.panel.tls", "для своего сертификата нужны пути к сертификату и ключу")
		}
	case "acme":
		r.errf("system.panel.tls.mode", "автоматический выпуск сертификата ACME ещё не реализован")
	default:
		r.errf("system.panel.tls.mode", "неизвестный режим TLS %q", c.System.Panel.TLS.Mode)
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
	for i, channel := range c.Channels {
		if channel.Enabled && channel.Type == "wireguard" && !c.HasComponent("wireguard") {
			r.errf(fmt.Sprintf("channels[%d].enabled", i),
				"для канала WireGuard нужен компонент «WireGuard»")
		}
		if channel.Enabled && channel.Type == "openconnect" && !c.HasComponent("openconnect") {
			r.errf(fmt.Sprintf("channels[%d].enabled", i),
				"для канала OpenConnect нужен компонент «OpenConnect»")
		}
		if channel.Enabled && channel.Type == "xray" && !c.HasComponent("xray") {
			r.errf(fmt.Sprintf("channels[%d].enabled", i),
				"для канала Xray нужен компонент «Xray»")
		}
	}
	for i, server := range c.VPNServers {
		if server.Enabled && server.Type == "wireguard" && !c.HasComponent("wireguard") {
			r.errf(fmt.Sprintf("vpn_servers[%d].enabled", i),
				"для сервера WireGuard нужен компонент «WireGuard»")
		}
		if server.Enabled && server.Type == "xray" && !c.HasComponent("xray") {
			r.errf(fmt.Sprintf("vpn_servers[%d].enabled", i),
				"для сервера Xray нужен компонент «Xray»")
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

		switch {
		case iface.Name == "":
			r.errf(path+".name", "пустое имя интерфейса")
		case names[iface.Name]:
			r.errf(path+".name", "интерфейс %q объявлен дважды", iface.Name)
		case !ValidInterfaceName(iface.Name):
			// Ядро обрежет длинное имя молча, а на имя ссылаются зоны
			// файрволла: правило уйдёт в пустоту, и это не будет видно нигде.
			r.errf(path+".name",
				"имя %q ядро не примет: не длиннее %d символов, без пробелов и косых черт",
				iface.Name, maxInterfaceName)
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

	c.validateTopology(r)
}

// validateTopology проверяет связи между интерфейсами на выполнимость.
//
// Панель позволяет выбрать что угодно, а ядро — нет: порт входит ровно в один
// мост, подчинённый порт не имеет своего адреса, мост нельзя вложить в мост.
// Раньше такие сочетания принимались молча и применялись частично:
// администратор видел в панели одну картину, а в ip a другую.
func (c *Config) validateTopology(r *ValidationResult) {
	byID := map[string]Interface{}
	for _, i := range c.Interfaces {
		byID[i.ID] = i
	}
	// Владелец порта: в какой мост или агрегацию он уже включён.
	owner := map[string]string{}
	for _, i := range c.Interfaces {
		if i.Type != "bridge" && i.Type != "bond" {
			continue
		}
		for _, m := range i.Members {
			if owner[m] == "" {
				owner[m] = i.Name
			}
		}
	}

	vlanTaken := map[string]string{} // родитель+номер → имя VLAN

	for i, iface := range c.Interfaces {
		path := fmt.Sprintf("interfaces[%d]", i)

		seen := map[string]bool{}
		for _, m := range iface.Members {
			member, ok := byID[m]
			if !ok {
				r.errf(path+".members", "порт %q не существует", m)
				continue
			}
			if m == iface.ID {
				r.errf(path+".members", "интерфейс %q включён сам в себя", iface.Name)
				continue
			}
			if seen[m] {
				r.errf(path+".members", "порт %q указан дважды", member.Name)
			}
			seen[m] = true

			// Мост в мост ядро не вкладывает: подчинить можно только порт.
			if member.Type == "bridge" {
				r.errf(path+".members",
					"мост %q нельзя включить в %q: ядро подчиняет мосту только порты и VLAN",
					member.Name, iface.Name)
			}
			if member.Type == "bond" && iface.Type == "bond" {
				r.errf(path+".members", "агрегацию %q нельзя включить в агрегацию %q",
					member.Name, iface.Name)
			}
			// Порт принадлежит ровно одному мосту: второй хозяин означает, что
			// применится тот, кто окажется последним, — и не тот, кого выбрали.
			if own := owner[m]; own != "" && own != iface.Name {
				r.errf(path+".members",
					"порт %q уже входит в %q: включить его можно только куда-то одно",
					member.Name, own)
			}
			if !member.Enabled {
				r.warnf(path+".members", "порт %q выключен и трафик через %q не пойдёт",
					member.Name, iface.Name)
			}
		}

		if iface.Type != "vlan" {
			continue
		}
		parent, ok := byID[iface.Parent]
		if iface.Parent == "" {
			continue // уже сообщили выше
		}
		if !ok {
			r.errf(path+".parent", "родительский интерфейс %q не существует", iface.Parent)
			continue
		}
		if parent.ID == iface.ID {
			r.errf(path+".parent", "VLAN %q поднят сам над собой", iface.Name)
			continue
		}
		if parent.Type == "vlan" {
			r.errf(path+".parent",
				"VLAN поверх VLAN (%q над %q) netOS не настраивает", iface.Name, parent.Name)
		}
		// Подчинённый порт отдаёт весь трафик мосту. VLAN, поднятый над ним,
		// не увидит ничего: тегированный трафик уйдёт в мост целиком.
		if own := owner[parent.ID]; own != "" {
			r.errf(path+".parent",
				"родитель %q входит в %q: весь его трафик уходит туда, и VLAN %q останется пустым",
				parent.Name, own, iface.Name)
		}
		key := fmt.Sprintf("%s/%d", iface.Parent, iface.VLANID)
		if other, taken := vlanTaken[key]; taken {
			r.errf(path+".vlan_id", "VLAN %d на %q уже описан интерфейсом %q",
				iface.VLANID, parent.Name, other)
		}
		vlanTaken[key] = iface.Name
	}

	c.validateInterfaceUse(r, owner, byID)
}

// validateInterfaceUse следит, чтобы адрес не назначали туда, где его быть не
// может, и чтобы один интерфейс не занимали дважды.
func (c *Config) validateInterfaceUse(r *ValidationResult, owner map[string]string, byID map[string]Interface) {
	// Сегмент и аплинк на одном интерфейсе несовместимы: подсистема аплинков
	// снимает с него все адреса, кроме своего, — локальный сегмент исчезнет
	// при первом же применении, и притом молча.
	type use struct{ kind, by string }
	usedBy := map[string]use{}
	claim := func(path, id string, u use) {
		if id == "" {
			return
		}
		prev, taken := usedBy[id]
		switch {
		case !taken:
			usedBy[id] = u
		case prev.kind != u.kind:
			r.errf(path+".interface",
				"на интерфейсе уже %s: аплинк и локальный сегмент на одной карте не уживаются",
				prev.by)
		case u.kind == "wan":
			r.errf(path+".interface", "на интерфейсе уже %s: двух аплинков на одной карте не бывает", prev.by)
		default:
			// Несколько подсетей на одном интерфейсе ядро принимает, но клиенты
			// увидят друг друга: это одна широковещательная область.
			r.warnf(path+".interface",
				"на интерфейсе уже %s: сегменты окажутся в одной широковещательной области", prev.by)
		}
	}

	for i, n := range c.Networks {
		path := fmt.Sprintf("networks[%d]", i)
		iface, ok := byID[n.Interface]
		if !ok {
			continue // об этом сообщает validateNetworks
		}
		if own := owner[n.Interface]; own != "" {
			r.errf(path+".interface",
				"порт %q входит в мост %q и своего адреса не имеет: назначьте сегмент самому мосту",
				iface.Name, own)
		}
		if n.Enabled {
			claim(path, n.Interface, use{"network", "сегмент «" + n.Name + "»"})
		}
	}
	for i, w := range c.WANs {
		path := fmt.Sprintf("wans[%d]", i)
		iface, ok := byID[w.Interface]
		if !ok {
			continue // об этом сообщает validateWANs
		}
		if own := owner[w.Interface]; own != "" {
			r.errf(path+".interface",
				"порт %q входит в мост %q: аплинк на подчинённом порту не поднимется",
				iface.Name, own)
		}
		if w.Enabled {
			// Выключенный интерфейс аплинку не помеха: подсистема аплинков
			// поднимает линк сама — на нём работает клиент DHCP или PPPoE.
			claim(path, w.Interface, use{"wan", "аплинк «" + w.Name + "»"})
		}
	}
}

func (c *Config) validateNetworks(r *ValidationResult) {
	ifaceIDs := c.interfaceIDs()
	zones := c.zoneNames()
	channels := c.usableChannelIDs()

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
			r.errf(path+".default_channel", "канал %q не существует или выключен", n.DefaultChannel)
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
	indexOwner := map[int]string{}
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
		if w.Index == 0 && c.MultiWAN.Enabled {
			r.errf(path+".index", "для Multi-WAN нужен стабильный индекс аплинка")
		} else if w.Index < 0 || w.Index > 999 {
			r.errf(path+".index", "индекс аплинка должен быть в диапазоне 1-999")
		} else if w.Index > 0 && indexOwner[w.Index] != "" {
			previous := indexOwner[w.Index]
			r.errf(path+".index", "индекс %d уже занят аплинком %q", w.Index, previous)
		}
		if w.Index > 0 {
			indexOwner[w.Index] = w.ID
		}
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
		validateProbe(r, path+".probe", w.Probe)
	}
	if enabled == 0 && len(c.Networks) > 0 {
		r.warnf("wans", "нет ни одного включённого аплинка — выхода в интернет не будет")
	}
	if enabled > 1 && !c.MultiWAN.Enabled {
		r.warnf("multiwan.enabled",
			"включено несколько аплинков, но Multi-WAN выключен — использоваться будет только один")
	}
	if c.MultiWAN.Enabled {
		if enabled < 2 {
			r.warnf("multiwan.enabled", "для Multi-WAN нужно хотя бы два включённых аплинка")
		}
		switch c.MultiWAN.Mode {
		case "failover":
		case "balance":
			for i, wan := range c.WANs {
				if wan.Enabled && wan.Weight < 1 {
					r.errf(fmt.Sprintf("wans[%d].weight", i), "вес должен быть положительным")
				}
			}
		default:
			r.errf("multiwan.mode", "неизвестный режим Multi-WAN %q", c.MultiWAN.Mode)
		}
	}
}

func validateProbe(r *ValidationResult, path string, p Probe) {
	if !p.Enabled {
		return
	}
	switch p.Type {
	case "icmp", "tcp", "http":
	default:
		r.errf(path+".type", "неизвестный тип проверки %q", p.Type)
	}
	if len(p.Targets) == 0 {
		r.errf(path+".targets", "нужна хотя бы одна цель проверки")
	}
	for i, target := range p.Targets {
		targetPath := fmt.Sprintf("%s.targets[%d]", path, i)
		switch p.Type {
		case "icmp":
			if net.ParseIP(target) == nil {
				r.errf(targetPath, "для ICMP нужен IP-адрес")
			}
		case "tcp":
			host, port, err := net.SplitHostPort(target)
			if err != nil || host == "" || !inPortRange(port) {
				r.errf(targetPath, "цель TCP должна быть в формате host:port")
			}
		case "http":
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				r.errf(targetPath, "цель HTTP должна начинаться с http:// или https://")
			}
		}
	}
	if p.Interval < 1 || p.Interval > 3600 {
		r.errf(path+".interval", "интервал должен быть 1-3600 секунд")
	}
	if p.Timeout < 1 || p.Timeout > 60 {
		r.errf(path+".timeout", "таймаут должен быть 1-60 секунд")
	}
	if p.FailThreshold < 1 || p.FailThreshold > 100 {
		r.errf(path+".fail_threshold", "порог отказа должен быть 1-100")
	}
	if p.RiseThreshold < 1 || p.RiseThreshold > 100 {
		r.errf(path+".rise_threshold", "порог восстановления должен быть 1-100")
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

	channels := c.usableChannelIDs()
	upstreams := map[string]bool{}
	upstreamByID := map[string]Upstream{}
	channelOwner := map[string]string{}
	secure := 0

	for i, u := range c.DNS.Upstreams {
		path := fmt.Sprintf("dns.upstreams[%d]", i)
		upstreams[u.ID] = true
		upstreamByID[u.ID] = u
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
		} else if u.Channel != "" {
			channelOwner[u.ID] = u.Channel
			if u.Channel != "direct" {
				if _, err := DNSUpstreamEndpoints(u); err != nil {
					r.errf(path+".address", "%v", err)
				}
			}
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

	// Резолвер роутера netOS забирает себе, но указать порт в /etc/resolv.conf
	// нечем: системные утилиты ходят только на 53. На другом порту резолвер
	// остаётся клиентам, а сама машина продолжит спрашивать имена у системного
	// резолвера — мимо шифрования и фильтров.
	if c.DNS.Enabled && c.DNS.Port != 53 {
		r.warnf("dns.port",
			"на порту %d резолвером будет пользоваться только сеть: сам роутер указать порт в /etc/resolv.conf не может и продолжит ходить за именами мимо него",
			c.DNS.Port)
	}

	// Имена клиентов знает только тот, кто раздал им адреса, а отдать их
	// резолверу умеет один dnsmasq: он поднимается подчинённым на loopback, и
	// выбранный резолвер направляет к нему локальный домен. С ISC DHCP или Kea
	// такого моста нет — локальные имена не разрешатся ни у кого, и молчать об
	// этом нельзя: администратор видит в настройках локальный домен и считает,
	// что имена работают.
	if c.DNS.Enabled && c.DNS.Provider != "dnsmasq" &&
		c.DHCP.Enabled && c.DHCP.Provider != "dnsmasq" {
		r.warnf("dhcp.provider",
			"имена клиентов, выданные по DHCP, разрешаться не будут: отдать их резолверу умеет только dnsmasq — выберите его сервером DHCP или задавайте имена вручную в записях DNS")
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
		} else if rule.Enabled && rule.Channel != "" {
			if rule.Upstream == "" {
				r.errf(path+".upstream", "для привязки split-DNS к каналу нужен отдельный апстрим")
				continue
			}
			if previous := channelOwner[rule.Upstream]; previous != "" && previous != rule.Channel {
				r.errf(path+".channel", "апстрим уже привязан к каналу %q; один DNS-сервер нельзя одновременно маршрутизировать через разные каналы", previous)
				continue
			}
			channelOwner[rule.Upstream] = rule.Channel
			if rule.Channel != "direct" {
				if up, ok := upstreamByID[rule.Upstream]; ok {
					if _, err := DNSUpstreamEndpoints(up); err != nil {
						r.errf(path+".upstream", "%v", err)
					}
				}
			}
		}
	}
	for i, blocklist := range c.DNS.Blocklists {
		if blocklist.Enabled {
			r.errf(fmt.Sprintf("dns.blocklists[%d].enabled", i),
				"загрузка и применение списков блокировки ещё не реализованы")
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
		if ch.Enabled && ch.Type != "direct" && ch.Type != "wireguard" && ch.Type != "openconnect" && ch.Type != "xray" {
			r.errf(path+".enabled", "каналы типа %s ещё не реализованы", ch.Type)
		}
		if ch.Index < 0 || ch.Index > 9999 || (ch.Type != "direct" && ch.Index == 0) {
			r.errf(path+".index", "индекс канала должен быть в диапазоне 1-9999")
		}
		if ch.Type == "wireguard" {
			c.validateWireGuardChannel(r, path, ch)
		}
		if ch.Type == "openconnect" {
			c.validateOpenConnectChannel(r, path, ch)
		}
		if ch.Type == "xray" {
			c.validateXrayChannel(r, path, ch)
		}
		if ch.Type != "direct" {
			validateProbe(r, path+".probe", ch.Probe)
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
			if !next.Enabled {
				r.errf("channels", "канал %q ссылается на выключенный запасной %q", cur.ID, cur.Fallback)
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

func (c *Config) validateXrayChannel(r *ValidationResult, path string, ch Channel) {
	if ch.Mode != "tun" {
		r.errf(path+".mode", "Xray работает в netOS только через безопасный TUN-контур")
	}
	xr, err := ch.XrayConfig()
	if err != nil {
		r.errf(path+".config", "%v", err)
		return
	}
	if xr.MTU != 0 && (xr.MTU < 576 || xr.MTU > 9000) {
		r.errf(path+".config.mtu", "MTU вне диапазона 576-9000")
	}
	protocol, _ := xr.Outbound["protocol"].(string)
	switch protocol {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "freedom":
	default:
		r.errf(path+".config.outbound.protocol", "неподдерживаемый протокол Xray %q", protocol)
	}
	if _, ok := xr.Outbound["settings"]; !ok {
		r.errf(path+".config.outbound.settings", "укажите настройки исходящего подключения Xray")
	}
}

func (c *Config) validateWireGuardChannel(r *ValidationResult, path string, ch Channel) {
	if ch.Mode != "tun" {
		r.errf(path+".mode", "WireGuard работает только в режиме TUN")
	}
	wg, err := ch.WireGuardConfig()
	if err != nil {
		r.errf(path+".config", "%v", err)
		return
	}
	if prefix, err := netip.ParsePrefix(wg.Address); err != nil || !prefix.Addr().Is4() {
		r.errf(path+".config.address", "нужен IPv4-адрес туннеля с маской")
	}
	validateWGKey(r, path+".config.private_key", wg.PrivateKey, false)
	validateWGKey(r, path+".config.peer_public_key", wg.PeerPublicKey, false)
	validateWGKey(r, path+".config.preshared_key", wg.PresharedKey, true)
	if host, port, err := net.SplitHostPort(wg.Endpoint); err != nil || host == "" || !inPortRange(port) {
		r.errf(path+".config.endpoint", "endpoint должен быть в формате host:port")
	}
	if len(wg.AllowedIPs) == 0 {
		r.errf(path+".config.allowed_ips", "нужна хотя бы одна разрешённая подсеть")
	}
	hasDefault := false
	for i, cidr := range wg.AllowedIPs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() {
			r.errf(fmt.Sprintf("%s.config.allowed_ips[%d]", path, i), "некорректная IPv4-подсеть")
		} else if prefix == netip.MustParsePrefix("0.0.0.0/0") {
			hasDefault = true
		}
	}
	if !hasDefault {
		r.errf(path+".config.allowed_ips", "исходящий канал должен включать 0.0.0.0/0")
	}
	if wg.PersistentKeepalive < 0 || wg.PersistentKeepalive > 65535 {
		r.errf(path+".config.persistent_keepalive", "значение должно быть в диапазоне 0-65535 секунд")
	}
	if wg.MTU != 0 && (wg.MTU < 576 || wg.MTU > 9000) {
		r.errf(path+".config.mtu", "MTU вне диапазона 576-9000")
	}
}

func validateWGKey(r *ValidationResult, path, value string, optional bool) {
	if optional && value == "" {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		r.errf(path, "ключ WireGuard должен быть base64 от 32 байт")
	}
}

func (c *Config) validateOpenConnectChannel(r *ValidationResult, path string, ch Channel) {
	if ch.Mode != "tun" {
		r.errf(path+".mode", "OpenConnect работает только в режиме TUN")
	}
	oc, err := ch.OpenConnectConfig()
	if err != nil {
		r.errf(path+".config", "%v", err)
		return
	}
	if oc.Server == "" {
		r.errf(path+".config.server", "укажите адрес VPN-сервера")
	} else if parsed, err := url.Parse(oc.Server); err != nil || parsed.Host == "" || parsed.Scheme != "https" {
		r.errf(path+".config.server", "сервер должен быть URL вида https://vpn.example.com")
	}
	if oc.Username == "" {
		r.errf(path+".config.username", "укажите имя пользователя")
	}
	if oc.Password == "" {
		r.errf(path+".config.password", "укажите пароль")
	}
	for field, value := range map[string]string{
		"username": oc.Username, "password": oc.Password, "authgroup": oc.AuthGroup, "servercert": oc.ServerCert,
	} {
		if strings.ContainsAny(value, "\r\n") {
			r.errf(path+".config."+field, "переводы строк недопустимы")
		}
	}
	if oc.NoSystemTrust && oc.ServerCert == "" {
		r.errf(path+".config.servercert", "при отключённом системном доверии нужен отпечаток сертификата")
	}
	switch oc.Protocol {
	case "", "anyconnect", "nc", "pulse", "gp", "f5", "fortinet", "array":
	default:
		r.errf(path+".config.protocol", "неизвестный протокол OpenConnect %q", oc.Protocol)
	}
	if oc.MTU != 0 && (oc.MTU < 576 || oc.MTU > 9000) {
		r.errf(path+".config.mtu", "MTU вне диапазона 576-9000")
	}
}

func (c *Config) validatePolicies(r *ValidationResult) {
	channels := c.usableChannelIDs()
	networks := c.networkIDs()
	servers := map[string]bool{}
	serverTypes := map[string]string{}
	serverPeers := map[string]map[string]bool{}
	for _, s := range c.VPNServers {
		servers[s.ID] = true
		serverTypes[s.ID] = s.Type
		serverPeers[s.ID] = map[string]bool{}
		for _, peer := range s.Peers {
			serverPeers[s.ID][peer.ID] = true
		}
	}

	ids := map[string]bool{}
	for i, p := range c.Policies {
		path := fmt.Sprintf("policies[%d]", i)
		if p.ID == "" || ids[p.ID] {
			r.errf(path+".id", "пустой или повторяющийся идентификатор политики")
		}
		ids[p.ID] = true
		if !channels[p.Channel] {
			r.errf(path+".channel", "канал %q не существует или выключен", p.Channel)
		}
		if p.Network != "" && !networks[p.Network] {
			r.errf(path+".network", "неизвестный сегмент %q", p.Network)
		}
		if p.VPNServer != "" && !servers[p.VPNServer] {
			r.errf(path+".vpn_server", "неизвестный VPN-сервер %q", p.VPNServer)
		}
		if p.VPNPeer != "" && p.VPNServer == "" {
			r.errf(path+".vpn_peer", "для выбора VPN-пира сначала укажите VPN-сервер")
		} else if p.VPNPeer != "" && !serverPeers[p.VPNServer][p.VPNPeer] {
			r.errf(path+".vpn_peer", "неизвестный VPN-пир %q", p.VPNPeer)
		}
		if serverTypes[p.VPNServer] == "xray" {
			if p.SrcIP != "" || p.SrcMAC != "" || p.Network != "" || p.Schedule != nil {
				r.errf(path, "для Xray-сервера доступны условия по клиенту, протоколу, адресу и порту назначения")
			}
			if p.Protocol == "icmp" {
				r.errf(path+".protocol", "VLESS не передаёт ICMP")
			}
		}
		if p.Enabled && len(p.Domains) > 0 {
			r.errf(path+".domains", "выбор трафика по доменам ещё не реализован")
		}
		switch p.Protocol {
		case "", "any", "tcp", "udp", "icmp":
		default:
			r.errf(path+".protocol", "поддерживаются протоколы TCP, UDP, ICMP или any")
		}
		if p.DstPort != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
			r.errf(path+".protocol", "для политики с портами нужно выбрать TCP или UDP")
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
	channels := c.usableChannelIDs()
	ports := map[int]string{}
	ids := map[string]bool{}
	indexes := map[int]bool{}
	for i, s := range c.VPNServers {
		path := fmt.Sprintf("vpn_servers[%d]", i)
		if s.ID == "" || ids[s.ID] {
			r.errf(path+".id", "пустой или повторяющийся идентификатор VPN-сервера")
		}
		ids[s.ID] = true
		if s.Index < 1 || s.Index > 9999 || indexes[s.Index] {
			r.errf(path+".index", "индекс VPN-сервера должен быть уникальным числом 1-9999")
		}
		indexes[s.Index] = true
		if s.Enabled && s.Type != "wireguard" && s.Type != "xray" {
			r.errf(path+".enabled", "VPN-серверы типа %s ещё не реализованы", s.Type)
		}
		switch s.Type {
		case "wireguard", "ikev2", "ocserv", "xray":
		default:
			r.errf(path+".type", "неизвестный тип VPN-сервера %q", s.Type)
		}
		subnet, err := netip.ParsePrefix(s.Subnet)
		if err != nil || !subnet.Addr().Is4() {
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
		if s.Type == "wireguard" {
			c.validateWireGuardServer(r, path, s)
		}
		if s.Type == "xray" {
			c.validateXrayServer(r, path, s)
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

func (c *Config) validateXrayServer(r *ValidationResult, path string, s VPNServer) {
	xr, err := s.XrayConfig()
	if err != nil {
		r.errf(path+".config", "%v", err)
		return
	}
	if !s.Enabled {
		return
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(xr.PrivateKey, "="))
	if err != nil || len(key) != 32 {
		r.errf(path+".config.private_key", "закрытый ключ Reality должен содержать 32 байта в base64url")
	}
	if host, port, err := net.SplitHostPort(xr.Destination); err != nil || host == "" || !inPortRange(port) {
		r.errf(path+".config.destination", "цель маскировки должна быть в формате www.example.com:443")
	}
	if xr.PublicEndpoint != "" {
		if host, port, err := net.SplitHostPort(xr.PublicEndpoint); err != nil || host == "" || !inPortRange(port) {
			r.errf(path+".config.public_endpoint", "публичный адрес должен быть в формате vpn.example.com:443")
		}
	}
	if len(xr.ServerNames) == 0 {
		r.errf(path+".config.server_names", "укажите хотя бы одно имя сервера Reality")
	}
	if len(xr.ShortIDs) == 0 {
		r.errf(path+".config.short_ids", "укажите хотя бы один short ID Reality")
	}
	for i, id := range xr.ShortIDs {
		if len(id) == 0 || len(id) > 16 || len(id)%2 != 0 {
			r.errf(fmt.Sprintf("%s.config.short_ids[%d]", path, i), "short ID должен содержать чётное число hex-символов, не больше 16")
			continue
		}
		if _, err := hex.DecodeString(id); err != nil {
			r.errf(fmt.Sprintf("%s.config.short_ids[%d]", path, i), "short ID должен быть шестнадцатеричным")
		}
	}
	if s.Port < 1 || s.Port > 65535 {
		r.errf(path+".port", "порт должен быть в диапазоне 1-65535")
	}
	seenUUID := map[string]bool{}
	for i, peer := range s.Peers {
		if peer.ID == "" {
			r.errf(fmt.Sprintf("%s.peers[%d].id", path, i), "пустой идентификатор клиента")
		}
		uuid := strings.ToLower(peer.Credentials["uuid"])
		if !validUUID(uuid) {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.uuid", path, i), "некорректный UUID клиента")
		}
		if uuid != "" && seenUUID[uuid] {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.uuid", path, i), "UUID уже назначен другому клиенту")
		}
		seenUUID[uuid] = true
	}
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

func (c *Config) validateWireGuardServer(r *ValidationResult, path string, s VPNServer) {
	wg, err := s.WireGuardConfig()
	if err != nil {
		r.errf(path+".config", "%v", err)
		return
	}
	if !s.Enabled {
		return
	}
	validateWGKey(r, path+".config.private_key", wg.PrivateKey, false)
	if wg.MTU != 0 && (wg.MTU < 576 || wg.MTU > 9000) {
		r.errf(path+".config.mtu", "MTU вне диапазона 576-9000")
	}
	if wg.PublicEndpoint != "" {
		if host, port, err := net.SplitHostPort(wg.PublicEndpoint); err != nil || host == "" || !inPortRange(port) {
			r.errf(path+".config.public_endpoint", "публичный адрес должен быть в формате vpn.example.com:51820")
		}
	}
	for i, address := range wg.ClientDNS {
		if parsed := net.ParseIP(address); parsed == nil {
			r.errf(fmt.Sprintf("%s.config.client_dns[%d]", path, i), "некорректный адрес DNS-сервера")
		}
	}
	for i, cidr := range wg.ClientAllowedIPs {
		if prefix, err := netip.ParsePrefix(cidr); err != nil || !prefix.Addr().Is4() {
			r.errf(fmt.Sprintf("%s.config.client_allowed_ips[%d]", path, i), "некорректная IPv4-подсеть")
		}
	}
	if len(wg.ClientAllowedIPs) == 0 {
		r.errf(path+".config.client_allowed_ips", "укажите хотя бы одну подсеть для клиентов")
	}
	if s.Port < 1 || s.Port > 65535 {
		r.errf(path+".port", "порт должен быть в диапазоне 1-65535")
	}
	serverPrefix, prefixErr := netip.ParsePrefix(s.Subnet)
	seenKeys := map[string]bool{}
	seenIDs := map[string]bool{}
	for i, peer := range s.Peers {
		ppath := fmt.Sprintf("%s.peers[%d]", path, i)
		if peer.ID == "" || seenIDs[peer.ID] {
			r.errf(ppath+".id", "пустой или повторяющийся идентификатор пира")
		}
		seenIDs[peer.ID] = true
		publicKey := peer.Credentials["public_key"]
		validateWGKey(r, ppath+".credentials.public_key", publicKey, false)
		if publicKey != "" && seenKeys[publicKey] {
			r.errf(ppath+".credentials.public_key", "этот публичный ключ уже назначен другому пиру")
		}
		seenKeys[publicKey] = true
		validateWGKey(r, ppath+".credentials.preshared_key", peer.Credentials["preshared_key"], true)
		if addr, err := netip.ParseAddr(peer.Address); err == nil && prefixErr == nil && addr == serverPrefix.Addr() {
			r.errf(ppath+".address", "адрес сервера нельзя назначить клиенту")
		}
	}
}

func (c *Config) validateWiFi(r *ValidationResult) {
	networks := c.networkIDs()
	for i, radio := range c.WiFi {
		path := fmt.Sprintf("wifi[%d]", i)
		if radio.Enabled {
			r.errf(path+".enabled", "управление точкой доступа Wi-Fi ещё не реализовано")
		}
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

func (c *Config) usableChannelIDs() map[string]bool {
	m := map[string]bool{}
	for _, ch := range c.Channels {
		if ch.Enabled && (ch.Type == "direct" || ch.Type == "wireguard" || ch.Type == "openconnect" || ch.Type == "xray") {
			m[ch.ID] = true
		}
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

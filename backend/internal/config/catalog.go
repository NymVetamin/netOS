package config

// Каталог компонентов роутера.
//
// Базовая установка netOS ставит только панель. Всё остальное — DHCP-сервер,
// резолверы, VPN, точка доступа — это отдельные компоненты, которые
// администратор включает сам. Роутер, который никто не просил раздавать
// адреса, не должен поднимать DHCP-сервер только потому, что «так принято».

// ComponentInfo описывает один компонент каталога.
type ComponentInfo struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Group — раздел каталога в панели.
	Group string `json:"group"`
	// Description объясняет, зачем компонент нужен, обычными словами.
	Description string `json:"description"`
	// Packages — что ставится через apt.
	Packages []string `json:"packages"`
	// Units — штатные службы дистрибутива, которые netOS гасит после
	// установки пакета: демонами управляет он сам, своими юнитами.
	Units []string `json:"units,omitempty"`
	// RunUnits — юниты самого netOS, по которым видно, что компонент не просто
	// установлен, а работает. Имя может быть шаблоном: юниты аплинков
	// называются по идентификатору канала и заранее неизвестны.
	//
	// Пусто там, где работу компонента нечем измерить: ipset, iproute2 и
	// утилиты диагностики демонов не поднимают, и «используется» для них
	// означало бы лишь то, что пакет стоит.
	RunUnits []string `json:"run_units,omitempty"`
	// Provides — роли, которые компонент закрывает: dns, dhcp, vpn-client и так
	// далее. Панель по ним подсказывает, чего не хватает для нужной функции.
	Provides []string `json:"provides,omitempty"`
	// SizeHint — примерный объём после установки, чтобы выбор был осознанным.
	SizeHint string `json:"size_hint,omitempty"`
	// External означает, что компонент ставится не из репозиториев Debian, а
	// собственным установщиком.
	External bool `json:"external,omitempty"`
	// Essential запрещает удалять пакет вместе с выключением функции: пакет
	// входит в базовую систему и используется самим netOS.
	Essential bool `json:"essential,omitempty"`
}

// Catalog — полный список того, что netOS умеет устанавливать.
var Catalog = []ComponentInfo{
	// --- выдача адресов ---
	{
		ID: "dnsmasq", Title: "dnsmasq", Group: "DHCP службы",
		Description: "Лёгкий сервер DHCP и кэширующий DNS в одном процессе. Обычный выбор для домашнего роутера.",
		Packages:    []string{"dnsmasq"},
		// netOS запускает собственный экземпляр с генерируемым конфигом,
		// поэтому штатный юнит гасится сразу после установки пакета.
		Units:    []string{"dnsmasq.service"},
		RunUnits: []string{"netos-dnsmasq.service"},
		Provides: []string{"dhcp", "dns"},
		SizeHint: "около 1 МБ",
	},
	{
		ID: "isc-dhcp-server", Title: "ISC DHCP", Group: "DHCP службы",
		Description: "Классический сервер DHCP с богатым набором опций. Знаком администраторам корпоративных сетей.",
		Packages:    []string{"isc-dhcp-server"},
		Units:       []string{"isc-dhcp-server.service"},
		RunUnits:    []string{"netos-isc-dhcp.service"},
		Provides:    []string{"dhcp"},
		SizeHint:    "около 3 МБ",
	},
	{
		ID: "kea", Title: "Kea DHCP", Group: "DHCP службы",
		Description: "Преемник ISC DHCP: управление через REST, хуки, отдельная база аренд.",
		Packages:    []string{"kea-dhcp4-server"},
		Units:       []string{"kea-dhcp4-server.service"},
		RunUnits:    []string{"netos-kea-dhcp4.service"},
		Provides:    []string{"dhcp"},
		SizeHint:    "около 12 МБ",
	},

	// --- резолверы ---
	{
		ID: "unbound", Title: "Unbound", Group: "DNS",
		Description: "Полноценный рекурсивный резолвер с проверкой DNSSEC и поддержкой DNS over TLS.",
		// unbound-anchor — отдельный пакет в Debian, без него не создать
		// якорь DNSSEC, и резолвер не поднимется с включённой проверкой.
		Packages: []string{"unbound", "unbound-anchor"},
		// unbound-resolvconf гасится вместе с самим unbound: он объявляет
		// резолвером роутера штатный экземпляр и падает на каждом запуске
		// («Link lo is loopback device»), оставаясь в состоянии failed. Резолвер
		// роутера принадлежит netOS, помощник для чужого экземпляра нам не нужен.
		Units:    []string{"unbound.service", "unbound-resolvconf.service"},
		RunUnits: []string{"netos-unbound.service"},
		Provides: []string{"dns", "dot"},
		SizeHint: "около 5 МБ",
	},
	{
		ID: "dnsproxy", Title: "dnsproxy", Group: "DNS",
		Description: "Шифрованный DNS во всех видах: DoT, DoH и DoQ, отдельные апстримы для отдельных доменов.",
		Provides:    []string{"dns", "dot", "doh", "doq"},
		SizeHint:    "около 20 МБ",
		RunUnits:    []string{"netos-dnsproxy.service"},
		External:    true,
	},
	{
		ID: "adguardhome", Title: "AdGuard Home", Group: "DNS",
		Description: "Шифрованный DNS плюс блокировка рекламы и трекеров, своя статистика запросов.",
		Provides:    []string{"dns", "dot", "doh", "doq", "adblock"},
		SizeHint:    "около 40 МБ",
		External:    true,
	},

	// --- VPN-клиенты ---
	{
		ID: "wireguard", Title: "WireGuard", Group: "VPN",
		Description: "Быстрый современный туннель. Работает в ядре, подходит и для исходящих каналов, и для приёма клиентов.",
		Packages:    []string{"wireguard-tools"},
		Provides:    []string{"vpn-client", "vpn-server"},
		SizeHint:    "меньше 1 МБ",
	},
	{
		ID: "xray", Title: "Xray", Group: "VPN",
		Description: "VLESS, VMess, Trojan, Shadowsocks с Reality и XTLS. Для каналов, которые должны выглядеть обычным трафиком.",
		Provides:    []string{"vpn-client", "vpn-server"},
		SizeHint:    "около 30 МБ",
		RunUnits:    []string{"netos-xray-*.service"},
		External:    true,
	},
	{
		ID: "openconnect", Title: "OpenConnect", Group: "VPN",
		Description: "Клиент для шлюзов Cisco AnyConnect, Pulse и Fortinet.",
		Packages:    []string{"openconnect"},
		Provides:    []string{"vpn-client"},
		SizeHint:    "около 2 МБ",
	},
	{
		ID: "strongswan", Title: "strongSwan", Group: "VPN",
		Description: "IPsec: каналы IKEv2 и приём подключений от встроенных клиентов iOS, macOS и Windows.",
		Packages:    []string{"strongswan", "strongswan-swanctl"},
		Units:       []string{"strongswan.service"},
		Provides:    []string{"vpn-client", "vpn-server"},
		SizeHint:    "около 15 МБ",
	},
	{
		ID: "l2tp", Title: "L2TP", Group: "Подключение к провайдеру",
		Description: "Нужен, если провайдер даёт интернет через туннель до своего концентратора по логину и паролю.",
		Packages:    []string{"xl2tpd", "ppp"},
		// Штатный юнит обязательно перечислен: без этого установка пакета
		// поднимает xl2tpd со своим конфигом, и он занимает порт 1701, на
		// котором должен работать туннель netOS.
		Units:    []string{"xl2tpd.service"},
		RunUnits: []string{"netos-l2tp-*.service"},
		Provides: []string{"vpn-client", "wan"},
		SizeHint: "около 2 МБ",
	},
	{
		ID: "ocserv", Title: "ocserv", Group: "VPN",
		Description: "Сервер OpenConnect. Маскируется под обычный HTTPS — помогает там, где режут WireGuard и IPsec.",
		Packages:    []string{"ocserv"},
		Units:       []string{"ocserv.service"},
		RunUnits:    []string{"netos-ocserv-srv*.service"},
		Provides:    []string{"vpn-server"},
		SizeHint:    "около 4 МБ",
	},

	// --- подключение к провайдеру ---
	{
		ID: "pppoe", Title: "PPPoE", Group: "Подключение к провайдеру",
		Description: "Нужен, если провайдер выдаёт интернет через логин и пароль по PPPoE.",
		Packages:    []string{"pppoe", "ppp"},
		RunUnits:    []string{"netos-pppoe-*.service"},
		Provides:    []string{"wan"},
		SizeHint:    "около 1 МБ",
	},

	// --- беспроводная сеть ---
	{
		ID: "hostapd", Title: "Точка доступа Wi-Fi", Group: "Беспроводная сеть",
		Description: "Раздача Wi-Fi с беспроводной карты роутера: WPA2 и WPA3, несколько сетей на одном радио.",
		Packages:    []string{"hostapd", "iw"},
		Units:       []string{"hostapd.service"},
		RunUnits:    []string{"netos-hostapd-*.service"},
		Provides:    []string{"wifi"},
		SizeHint:    "около 2 МБ",
	},

	// --- вспомогательное ---
	{
		ID: "ipset", Title: "Наборы адресов", Group: "Дополнительно",
		Description: "Позволяет правилам работать со списками адресов и доменов целиком. Нужен для маршрутизации по доменам.",
		Packages:    []string{"ipset"},
		Provides:    []string{"ipset"},
		SizeHint:    "меньше 1 МБ",
	},
	{
		ID: "diagnostics", Title: "Инструменты диагностики", Group: "Дополнительно",
		Description: "tcpdump, dig, traceroute и mtr — чтобы разбираться с сетью прямо на роутере.",
		Packages:    []string{"tcpdump", "dnsutils", "traceroute", "mtr-tiny"},
		SizeHint:    "около 10 МБ",
	},
	{
		ID: "qos", Title: "Ограничение скорости", Group: "Дополнительно",
		Description: "Шейпинг трафика и приоритеты для клиентов.",
		Packages:    []string{"iproute2"},
		Provides:    []string{"qos"},
		SizeHint:    "уже установлено",
		Essential:   true,
	},
}

// ComponentByID ищет описание компонента в каталоге.
func ComponentByID(id string) (ComponentInfo, bool) {
	for _, c := range Catalog {
		if c.ID == id {
			return c, true
		}
	}
	return ComponentInfo{}, false
}

// HasComponent сообщает, помечен ли компонент как установленный.
func (c *Config) HasComponent(id string) bool {
	for _, comp := range c.Components {
		if comp.ID == id {
			return comp.Installed
		}
	}
	return false
}

// ProvidersFor возвращает установленные компоненты, закрывающие указанную роль.
// Панель по этому списку показывает, из чего можно выбирать, и не предлагает
// того, что ещё не установлено.
func (c *Config) ProvidersFor(role string) []string {
	var out []string
	for _, comp := range c.Components {
		if !comp.Installed {
			continue
		}
		info, ok := ComponentByID(comp.ID)
		if !ok {
			continue
		}
		for _, p := range info.Provides {
			if p == role {
				out = append(out, comp.ID)
				break
			}
		}
	}
	return out
}

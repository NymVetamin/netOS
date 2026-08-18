package config

import "fmt"

// Default возвращает конфигурацию, с которой система запускается сразу после
// установки.
//
// Философия базовой установки: netOS разворачивает панель и оставляет доступ
// по SSH, больше ничего. Ни DHCP-сервера, ни резолвера, ни VPN — всё это
// администратор включает сам в разделе компонентов, когда решит, что оно ему
// нужно. Роутер не должен поднимать службы, которых у него не просили.
func Default() *Config {
	cfg := defaultConfig()
	// Системные правила — часть работоспособной конфигурации, а не украшение.
	// Без них применяется набор с политикой DROP и без единого разрешающего
	// правила, то есть роутер отрезает сам себя от сети.
	cfg.Normalize()
	return cfg
}

func defaultConfig() *Config {
	return &Config{
		Version: Version,
		System: System{
			Hostname:       "netos",
			Timezone:       "UTC",
			NetworkBackend: "netos",
			NTP: NTP{
				Enabled: true,
				Servers: []string{"0.debian.pool.ntp.org", "1.debian.pool.ntp.org"},
			},
			Panel: Panel{
				Port:          8443,
				CommitTimeout: 90,
				TLS:           TLS{Mode: "selfsigned"},
			},
		},
		IPv6: IPv6Policy{
			Mode:       "off",
			FilterAAAA: true,
		},
		Components: []Component{},
		Interfaces: []Interface{},
		Networks:   []Network{},
		WANs:       []WAN{},
		MultiWAN: MultiWAN{
			Enabled:           false,
			Mode:              "failover",
			StickyConnections: true,
		},
		Routing: Routing{
			Static: []StaticRoute{},
			Tables: []RouteTable{},
			Rules:  []RouteRule{},
		},
		Firewall: Firewall{
			Enabled:      true,
			OutputPolicy: "accept",
			Zones:        DefaultZones(),
			Rules:        []FirewallRule{},
			NAT:          []NATRule{},
		},
		DHCP: DHCP{
			Provider:     "",
			Enabled:      false,
			Reservations: []Reservation{},
		},
		DNS: DNS{
			Provider:         "",
			Enabled:          false,
			Port:             53,
			CacheSize:        4096,
			LocalDomain:      "lan",
			RebindProtection: true,
			Bootstrap:        []string{"1.1.1.1", "9.9.9.9"},
			Upstreams: []Upstream{
				{ID: "up-1", Type: "plain", Address: "1.1.1.1", Enabled: true, Comment: "Cloudflare"},
				{ID: "up-2", Type: "plain", Address: "9.9.9.9", Enabled: true, Comment: "Quad9"},
			},
			StaticRecords: []DNSRecord{},
			SplitRules:    []DNSSplitRule{},
			Blocklists:    []Blocklist{},
		},
		Clients: []Client{},
		Channels: []Channel{
			{ID: "direct", Index: 0, Name: "Напрямую", Enabled: true, Type: "direct", Mode: "tun", FailMode: "block"},
		},
		Policies:   []Policy{},
		VPNServers: []VPNServer{},
		WiFi:       []WiFiRadio{},
	}
}

// DefaultZones — три зоны, по которым раскладывается весь трафик.
func DefaultZones() []Zone {
	return []Zone{
		{
			Name: "lan", Title: "Локальная сеть", Policy: "accept",
			Description: "Устройства внутри сети, которым роутер доверяет.",
		},
		{
			Name: "wan", Title: "Интернет", Policy: "drop", MSSClamp: true,
			Description: "Всё, что приходит со стороны провайдера. По умолчанию не пропускается.",
		},
		{
			Name: "vpn", Title: "VPN", Policy: "accept", MSSClamp: true,
			Description: "Туннели: и каналы наружу, и подключившиеся клиенты.",
		},
	}
}

func DefaultProbe() Probe {
	return Probe{
		Enabled:       true,
		Type:          "icmp",
		Targets:       []string{"1.1.1.1", "8.8.8.8"},
		Interval:      10,
		Timeout:       3,
		FailThreshold: 3,
		RiseThreshold: 2,
	}
}

func DefaultDHCPPool(start, end string) DHCPPool {
	return DHCPPool{Enabled: true, Start: start, End: end, LeaseTime: 43200}
}

// ---------------------------------------------------------------------------
// Системные правила файрволла
// ---------------------------------------------------------------------------

// Системные правила — те, без которых роутер перестанет быть доступным или
// работоспособным. Они живут в общем списке правил и видны в панели наравне с
// остальными: администратор должен понимать, что именно защищает его доступ.
// Удалить их нельзя, выключить — можно, но панель предупредит о последствиях.
const (
	RuleLoopback       = "sys-loopback"
	RuleEstablishedIn  = "sys-established-in"
	RuleEstablishedFwd = "sys-established-fwd"
	RuleInvalidIn      = "sys-invalid-in"
	RuleInvalidFwd     = "sys-invalid-fwd"
	RuleSSH         = "sys-ssh"
	RulePanel       = "sys-panel"
	RuleICMP        = "sys-icmp"
	RuleDHCP        = "sys-dhcp"
	RuleDNSUDP      = "sys-dns-udp"
	RuleDNSTCP      = "sys-dns-tcp"
	RuleLANOut      = "sys-lan-out"
)

// systemRules возвращает эталонный набор в том порядке, в каком он должен
// стоять в начале списка.
func systemRules(panelPort int) []FirewallRule {
	return []FirewallRule{
		{
			ID: RuleLoopback, Name: "Локальная петля", System: true, Enabled: true,
			Zone: "global", Flow: "in", Action: "accept", Interface: "lo",
			Comment: "Обращения роутера к самому себе.",
		},
		{
			ID: RuleEstablishedIn, Name: "Ответы на запросы самого роутера", System: true, Enabled: true,
			Zone: "global", Flow: "in", Action: "accept", ConnState: "established,related",
			Comment: "Без этого правила ответы на исходящие запросы роутера не вернутся.",
		},
		{
			ID: RuleEstablishedFwd, Name: "Ответы на запросы клиентов", System: true, Enabled: true,
			Zone: "global", Flow: "forward", Action: "accept", ConnState: "established,related",
			Comment: "Без этого правила ответы из интернета не дойдут до клиентов.",
		},
		{
			ID: RuleInvalidIn, Name: "Отбрасывать некорректные пакеты к роутеру", System: true, Enabled: true,
			Zone: "global", Flow: "in", Action: "drop", ConnState: "invalid",
			Comment: "Пакеты, не относящиеся ни к одному известному соединению.",
		},
		{
			ID: RuleInvalidFwd, Name: "Отбрасывать некорректные транзитные пакеты", System: true, Enabled: true,
			Zone: "global", Flow: "forward", Action: "drop", ConnState: "invalid",
			Comment: "Пакеты, не относящиеся ни к одному известному соединению.",
		},
		{
			ID: RuleSSH, Name: "Доступ по SSH", System: true, Enabled: true,
			Zone: "global", Flow: "in", Action: "accept", Protocol: "tcp", DstPort: "22",
			Comment: "Аварийный доступ к роутеру. Выключайте, только если уверены в другом способе войти.",
		},
		{
			ID: RulePanel, Name: "Веб-панель netOS", System: true, Enabled: true,
			Zone: "global", Flow: "in", Action: "accept", Protocol: "tcp",
			DstPort: fmt.Sprint(panelPort),
			Comment: "Порт берётся из настроек панели в разделе «Система».",
		},
		{
			ID: RuleICMP, Name: "Отвечать на пинг", System: true, Enabled: true,
			Zone: "global", Flow: "in", Action: "accept", Protocol: "icmp",
			Comment: "Помогает проверять доступность роутера.",
		},
		{
			ID: RuleDHCP, Name: "Запросы DHCP из локальной сети", System: true, Enabled: true,
			Zone: "lan", Flow: "in", Action: "accept", Protocol: "udp", DstPort: "67",
			Comment: "Нужно, если роутер раздаёт адреса.",
		},
		{
			ID: RuleDNSUDP, Name: "Запросы DNS из локальной сети", System: true, Enabled: true,
			Zone: "lan", Flow: "in", Action: "accept", Protocol: "udp", DstPort: "53",
			Comment: "Нужно, если роутер работает резолвером.",
		},
		{
			ID: RuleDNSTCP, Name: "Запросы DNS из локальной сети (TCP)", System: true, Enabled: true,
			Zone: "lan", Flow: "in", Action: "accept", Protocol: "tcp", DstPort: "53",
			Comment: "Длинные ответы DNS передаются по TCP.",
		},
		{
			ID: RuleLANOut, Name: "Разрешить транзит из локальной сети в интернет", System: true, Enabled: true,
			Zone: "lan", Flow: "forward", DstZone: "wan", Action: "accept",
			Comment: "Разрешение пропускать пакеты. Адреса при этом не меняются — за подмену отвечает отдельное правило трансляции.",
		},
	}
}

// EnsureSystemRules достраивает недостающие системные правила и держит в
// актуальном состоянии те их поля, которыми владеет netOS.
//
// Пользовательские правки сохраняются: выключенное правило останется
// выключенным, суженный список источников — суженным.
func (c *Config) EnsureSystemRules() {
	existing := map[string]int{}
	for i, r := range c.Firewall.Rules {
		if r.System {
			existing[r.ID] = i
		}
	}

	var missing []FirewallRule
	for _, want := range systemRules(c.System.Panel.Port) {
		idx, ok := existing[want.ID]
		if !ok {
			missing = append(missing, want)
			continue
		}
		cur := &c.Firewall.Rules[idx]
		// Порт панели задаётся в другом разделе, и правило обязано за ним
		// следовать: иначе смена порта тихо отрежет доступ.
		if want.ID == RulePanel {
			cur.DstPort = want.DstPort
		}
		cur.System = true
		cur.Name = want.Name
		cur.Comment = want.Comment
	}

	// Системные правила идут первыми: они определяют доступность роутера,
	// и пользовательское правило не должно случайно оказаться выше.
	if len(missing) > 0 {
		c.Firewall.Rules = append(missing, c.Firewall.Rules...)
	}

}

// ---------------------------------------------------------------------------

// Normalize проставляет отсутствующие значения по умолчанию. Вызывается после
// разбора JSON, чтобы конфигурация со старой версии схемы не приводила к
// нулевым таймаутам и пустым политикам.
func (c *Config) Normalize() {
	if c.Version == 0 {
		c.Version = Version
	}
	if c.System.Panel.Port == 0 {
		c.System.Panel.Port = 8443
	}
	if c.System.Panel.CommitTimeout == 0 {
		c.System.Panel.CommitTimeout = 90
	}
	if c.System.Panel.TLS.Mode == "" {
		c.System.Panel.TLS.Mode = "selfsigned"
	}
	if c.System.NetworkBackend == "" {
		c.System.NetworkBackend = "netos"
	}
	if c.IPv6.Mode == "" {
		c.IPv6.Mode = "off"
	}
	if c.DNS.Port == 0 {
		c.DNS.Port = 53
	}
	if c.DNS.LocalDomain == "" {
		c.DNS.LocalDomain = "lan"
	}
	if c.MultiWAN.Mode == "" {
		c.MultiWAN.Mode = "failover"
	}
	if len(c.Firewall.Zones) == 0 {
		c.Firewall.Zones = DefaultZones()
	}
	if c.Components == nil {
		c.Components = []Component{}
	}

	for i := range c.WANs {
		if c.WANs[i].Metric == 0 {
			c.WANs[i].Metric = 100 + i
		}
		if c.WANs[i].Weight == 0 {
			c.WANs[i].Weight = 1
		}
		if c.WANs[i].Probe.Type == "" {
			c.WANs[i].Probe = DefaultProbe()
		}
	}
	for i := range c.Channels {
		if c.Channels[i].Mode == "" {
			c.Channels[i].Mode = "tun"
		}
		if c.Channels[i].FailMode == "" {
			c.Channels[i].FailMode = "block"
		}
		if c.Channels[i].Probe.Type == "" {
			c.Channels[i].Probe = DefaultProbe()
		}
	}
	for i := range c.Networks {
		if c.Networks[i].Zone == "" {
			c.Networks[i].Zone = "lan"
		}
		if c.Networks[i].DHCPPool.LeaseTime == 0 {
			c.Networks[i].DHCPPool.LeaseTime = 43200
		}
	}
	if c.Firewall.OutputPolicy == "" {
		c.Firewall.OutputPolicy = "accept"
	}
	for i := range c.Firewall.Rules {
		// Направление раньше называлось router; приводим к именам цепочек ядра.
		if c.Firewall.Rules[i].Flow == "router" {
			c.Firewall.Rules[i].Flow = "in"
		}
		// Направления «во все сразу» больше нет: старые правила приводим к входу.
		if c.Firewall.Rules[i].Flow == "any" || c.Firewall.Rules[i].Flow == "" {
			c.Firewall.Rules[i].Flow = "in"
		}
		if c.Firewall.Rules[i].Zone == "" {
			c.Firewall.Rules[i].Zone = "global"
		}
		// Зона назначения осмысленна только для форварда.
		if c.Firewall.Rules[i].Flow != "forward" {
			c.Firewall.Rules[i].DstZone = ""
		}
	}

	for i := range c.Firewall.NAT {
		if c.Firewall.NAT[i].Direction == "" {
			c.Firewall.NAT[i].Direction = "source"
		}
	}

	c.EnsureSystemRules()
}

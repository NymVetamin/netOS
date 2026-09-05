package config

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
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
	if c.Version != Version {
		r.errf("version", "неподдерживаемая версия схемы %d, ожидается %d", c.Version, Version)
	}

	c.validateObjectIDs(r)
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
	c.validateQoS(r)
	c.validateDDNS(r)

	return r
}

// validateObjectIDs applies one conservative syntax to identifiers that are
// reused in generated configuration, firewall comments, state keys, URLs and
// sometimes file/unit names.
func (c *Config) validateObjectIDs(r *ValidationResult) {
	check := func(path, value string) {
		if value != "" && !safeObjectID(value) {
			r.errf(path, "идентификатор может содержать только буквы, цифры, точку, дефис и подчёркивание")
		}
	}
	for i, v := range c.Interfaces {
		check(fmt.Sprintf("interfaces[%d].id", i), v.ID)
	}
	for i, v := range c.Networks {
		check(fmt.Sprintf("networks[%d].id", i), v.ID)
	}
	for i, v := range c.WANs {
		check(fmt.Sprintf("wans[%d].id", i), v.ID)
	}
	for i, v := range c.Routing.Static {
		check(fmt.Sprintf("routing.static[%d].id", i), v.ID)
	}
	for i, v := range c.Routing.Tables {
		check(fmt.Sprintf("routing.tables[%d].id", i), v.ID)
		check(fmt.Sprintf("routing.tables[%d].name", i), v.Name)
	}
	for i, v := range c.Routing.Rules {
		check(fmt.Sprintf("routing.rules[%d].id", i), v.ID)
	}
	for i, v := range c.Firewall.Zones {
		check(fmt.Sprintf("firewall.zones[%d].name", i), v.Name)
	}
	for i, v := range c.Firewall.Rules {
		check(fmt.Sprintf("firewall.rules[%d].id", i), v.ID)
	}
	for i, v := range c.Firewall.NAT {
		check(fmt.Sprintf("firewall.nat[%d].id", i), v.ID)
	}
	for i, v := range c.DHCP.Reservations {
		check(fmt.Sprintf("dhcp.reservations[%d].id", i), v.ID)
	}
	for i, v := range c.DNS.Upstreams {
		check(fmt.Sprintf("dns.upstreams[%d].id", i), v.ID)
	}
	for i, v := range c.DNS.StaticRecords {
		check(fmt.Sprintf("dns.static_records[%d].id", i), v.ID)
	}
	for i, v := range c.DNS.SplitRules {
		check(fmt.Sprintf("dns.split_rules[%d].id", i), v.ID)
	}
	for i, v := range c.DNS.Blocklists {
		check(fmt.Sprintf("dns.blocklists[%d].id", i), v.ID)
	}
	for i, v := range c.Clients {
		check(fmt.Sprintf("clients[%d].id", i), v.ID)
	}
	for i, v := range c.Channels {
		check(fmt.Sprintf("channels[%d].id", i), v.ID)
	}
	for i, v := range c.Policies {
		check(fmt.Sprintf("policies[%d].id", i), v.ID)
	}
	for i, v := range c.VPNServers {
		check(fmt.Sprintf("vpn_servers[%d].id", i), v.ID)
		for j, peer := range v.Peers {
			check(fmt.Sprintf("vpn_servers[%d].peers[%d].id", i, j), peer.ID)
		}
	}
	for i, v := range c.WiFi {
		check(fmt.Sprintf("wifi[%d].id", i), v.ID)
		for j, ssid := range v.SSIDs {
			check(fmt.Sprintf("wifi[%d].ssids[%d].id", i, j), ssid.ID)
		}
	}
}

func (c *Config) validateDDNS(r *ValidationResult) {
	if !c.DDNS.Enabled {
		return
	}
	if !validDNSName(c.DDNS.Hostname) || unsafeConfigText(c.DDNS.Hostname) {
		r.errf("ddns.hostname", "укажите корректное доменное имя")
	}
	if c.DDNS.Interval < 60 || c.DDNS.Interval > 86400 {
		r.errf("ddns.interval", "интервал должен быть от 60 до 86400 секунд")
	}
	if c.DDNS.AddressSource != "interface" && c.DDNS.AddressSource != "web" {
		r.errf("ddns.address_source", "неизвестный источник адреса %q", c.DDNS.AddressSource)
	}
	if c.DDNS.AddressSource == "interface" {
		found := false
		for _, wan := range c.WANs {
			if wan.ID == c.DDNS.WAN && wan.Enabled {
				found = true
			}
		}
		if !found {
			r.errf("ddns.wan", "выберите включённый интернет-канал")
		}
	}
	switch c.DDNS.Provider {
	case "duckdns":
		host := strings.ToLower(c.DDNS.Hostname)
		subdomain := strings.TrimSuffix(host, ".duckdns.org")
		if subdomain == host || subdomain == "" || strings.Contains(subdomain, ".") {
			r.errf("ddns.hostname", "для DuckDNS укажите имя вида example.duckdns.org")
		}
		if invalidDDNSSecret(c.DDNS.Token) {
			r.errf("ddns.token", "для DuckDNS нужен токен")
		}
	case "cloudflare":
		if invalidDDNSSecret(c.DDNS.Token) || invalidDDNSIdentifier(c.DDNS.ZoneID) || invalidDDNSIdentifier(c.DDNS.RecordID) {
			r.errf("ddns", "для Cloudflare нужны API-токен, Zone ID и Record ID")
		}
	case "noip":
		if invalidDDNSSecret(c.DDNS.Username) || strings.Contains(c.DDNS.Username, ":") || invalidDDNSSecret(c.DDNS.Password) {
			r.errf("ddns", "для No-IP нужны имя пользователя и пароль")
		}
	default:
		r.errf("ddns.provider", "неизвестный провайдер %q", c.DDNS.Provider)
	}
}

func invalidDDNSSecret(value string) bool {
	return value == "" || len(value) > 1024 || unsafeConfigText(value)
}

func invalidDDNSIdentifier(value string) bool {
	if value == "" || len(value) > 256 || unsafeConfigText(value) {
		return true
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return true
	}
	return false
}

func (c *Config) validateQoS(r *ValidationResult) {
	if !c.QoS.Enabled && len(c.QoS.WANs) == 0 {
		return
	}
	wanIDs := map[string]bool{}
	for _, wan := range c.WANs {
		wanIDs[wan.ID] = wan.Enabled
	}
	seen := map[string]int{}
	for i, item := range c.QoS.WANs {
		path := fmt.Sprintf("qos.wans[%d]", i)
		if !wanIDs[item.WAN] {
			r.errf(path+".wan", "интернет-канал %q не существует или выключен", item.WAN)
		} else if prev, ok := seen[item.WAN]; ok {
			r.errf(path+".wan", "интернет-канал уже настроен в qos.wans[%d]", prev)
		} else {
			seen[item.WAN] = i
		}
		if item.UploadKbit < 64 || item.UploadKbit > 10_000_000 {
			r.errf(path+".upload_kbit", "скорость должна быть от 64 до 10000000 Кбит/с")
		}
		if item.DownloadKbit < 64 || item.DownloadKbit > 10_000_000 {
			r.errf(path+".download_kbit", "скорость должна быть от 64 до 10000000 Кбит/с")
		}
		switch item.Diffserv {
		case "besteffort", "diffserv3", "diffserv4", "diffserv8":
		default:
			r.errf(path+".diffserv", "неизвестный профиль приоритетов %q", item.Diffserv)
		}
	}
	if c.QoS.Enabled && len(c.QoS.WANs) == 0 {
		r.errf("qos.wans", "добавьте хотя бы один интернет-канал")
	}
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
		} else if client.DownKbit > 0 && client.DownKbit < 64 {
			r.errf(path+".down_kbit", "минимальный лимит — 64 Кбит/с")
		} else if client.DownKbit > 10_000_000 {
			r.errf(path+".down_kbit", "максимальный лимит — 10000000 Кбит/с")
		}
		if client.UpKbit < 0 {
			r.errf(path+".up_kbit", "скорость не может быть отрицательной")
		} else if client.UpKbit > 0 && client.UpKbit < 64 {
			r.errf(path+".up_kbit", "минимальный лимит — 64 Кбит/с")
		} else if client.UpKbit > 10_000_000 {
			r.errf(path+".up_kbit", "максимальный лимит — 10000000 Кбит/с")
		}
		if (client.DownKbit > 0 || client.UpKbit > 0) && client.Network == "" {
			r.errf(path+".network", "для ограничения скорости выберите сегмент клиента")
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
	} else if !validDNSName(c.System.Hostname) {
		r.errf("system.hostname", "имя хоста должно быть корректным DNS-именем")
	}
	if !validTimezone(c.System.Timezone) {
		r.errf("system.timezone", "некорректный часовой пояс")
	}
	if c.System.NTP.Enabled && len(c.System.NTP.Servers) == 0 {
		r.errf("system.ntp.servers", "укажите хотя бы один сервер времени")
	}
	if len(c.System.NTP.Servers) > 8 {
		r.errf("system.ntp.servers", "можно указать не больше 8 серверов времени")
	}
	ntpServers := map[string]bool{}
	for i, server := range c.System.NTP.Servers {
		path := fmt.Sprintf("system.ntp.servers[%d]", i)
		if _, err := netip.ParseAddr(server); err != nil && !validDNSName(server) {
			r.errf(path, "сервер времени должен быть DNS-именем или IP-адресом")
		} else if ntpServers[strings.ToLower(server)] {
			r.errf(path, "сервер времени указан повторно")
		}
		ntpServers[strings.ToLower(server)] = true
	}
	if p := c.System.Panel.Port; p < 1 || p > 65535 {
		r.errf("system.panel.port", "порт панели вне диапазона 1-65535")
	}
	if c.DNS.Enabled && c.System.Panel.Port == c.DNS.Port {
		r.errf("system.panel.port", "порт панели совпадает с портом DNS")
	}
	if c.System.Panel.CommitTimeout < 1 || c.System.Panel.CommitTimeout > 86400 {
		r.errf("system.panel.commit_timeout",
			"время подтверждения должно быть в диапазоне 1-86400 секунд")
	} else if c.System.Panel.CommitTimeout < 15 {
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
		if c.System.Panel.TLS.CertFile == "" || unsafeConfigText(c.System.Panel.TLS.CertFile) {
			r.errf("system.panel.tls.cert_file", "укажите безопасный путь к файлу сертификата")
		}
		if c.System.Panel.TLS.KeyFile == "" || unsafeConfigText(c.System.Panel.TLS.KeyFile) {
			r.errf("system.panel.tls.key_file", "укажите безопасный путь к закрытому ключу")
		}
		if c.System.Panel.TLS.CertFile != "" && c.System.Panel.TLS.CertFile == c.System.Panel.TLS.KeyFile {
			r.errf("system.panel.tls.key_file", "сертификат и закрытый ключ должны находиться в разных файлах")
		}
	case "acme":
		domain := strings.TrimSuffix(strings.ToLower(c.System.Panel.TLS.Domain), ".")
		if c.System.Panel.Port == 80 {
			r.errf("system.panel.port", "порт 80 нужен для проверки домена ACME; выберите другой порт панели")
		}
		publicSuffix, icannSuffix := publicsuffix.PublicSuffix(domain)
		if domain == "" || unsafeConfigText(c.System.Panel.TLS.Domain) || net.ParseIP(domain) != nil || !validDNSName(domain) || !strings.Contains(domain, ".") || !icannSuffix || publicSuffix == domain {
			r.errf("system.panel.tls.domain", "укажите полное публичное DNS-имя")
		} else {
			for _, reserved := range []string{"local", "lan", "internal", "localhost", "test", "example", "invalid", "example.com", "example.net", "example.org", "home.arpa"} {
				if domain == reserved || strings.HasSuffix(domain, "."+reserved) {
					r.errf("system.panel.tls.domain", "ACME требует публичное DNS-имя, а не зарезервированную зону")
					break
				}
			}
		}
		if email := c.System.Panel.TLS.Email; email != "" {
			address, err := mail.ParseAddress(email)
			if err != nil || address.Address != email || len(email) > 254 || unsafeConfigText(email) {
				r.errf("system.panel.tls.email", "укажите обычный адрес электронной почты без имени и управляющих символов")
			}
		}
		if !c.System.Panel.TLS.AcceptTOS {
			r.errf("system.panel.tls.accept_tos", "подтвердите условия использования центра сертификации")
		}
	default:
		r.errf("system.panel.tls.mode", "неизвестный режим TLS %q", c.System.Panel.TLS.Mode)
	}
}

// validateComponents следит, чтобы выбранные службы были установлены. Без
// этого пользователь включит DHCP, а применение упадёт на отсутствующем пакете.
func (c *Config) validateComponents(r *ValidationResult) {
	seen := make(map[string]bool, len(c.Components))
	for i, comp := range c.Components {
		if _, ok := ComponentByID(comp.ID); !ok {
			r.errf(fmt.Sprintf("components[%d].id", i), "неизвестный компонент %q", comp.ID)
		} else if seen[comp.ID] {
			r.errf(fmt.Sprintf("components[%d].id", i), "компонент %q указан повторно", comp.ID)
		}
		seen[comp.ID] = true
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
		if server.Enabled && server.Type == "ocserv" && !c.HasComponent("ocserv") {
			r.errf(fmt.Sprintf("vpn_servers[%d].enabled", i),
				"для сервера OpenConnect нужен компонент «ocserv»")
		}
		if server.Enabled && server.Type == "ikev2" && !c.HasComponent("strongswan") {
			r.errf(fmt.Sprintf("vpn_servers[%d].enabled", i),
				"для сервера IKEv2 нужен компонент «strongSwan»")
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

	carrierOwner := map[string]string{}
	for i, iface := range c.Interfaces {
		if iface.Type != "bridge" || len(iface.Members) != 0 {
			continue
		}
		path := fmt.Sprintf("interfaces[%d].name", i)
		dummy, peer := BridgeCarrierNames(iface.Name)
		for _, generated := range []string{dummy, peer} {
			if names[generated] {
				r.errf(path, "служебный carrier пустого моста %q конфликтует с объявленным интерфейсом", generated)
			}
			if other := carrierOwner[generated]; other != "" && other != iface.Name {
				r.errf(path, "служебный carrier %q уже используется пустым мостом %q", generated, other)
			}
			carrierOwner[generated] = iface.Name
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
		// Кольцо: VLAN поднят над мостом, в который сам же и включён. Ядро
		// такую связь не строит и отвечает «Device or resource busy» уже на
		// применении — то есть посреди изменений, с откатом всей конфигурации.
		if own := owner[iface.ID]; own == parent.Name {
			r.errf(path+".parent",
				"VLAN %q нельзя поднять над %q: он сам входит в этот мост", iface.Name, parent.Name)
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
		if len(w.Username) > 256 || len(w.Password) > 1024 || strings.ContainsAny(w.Username+w.Password, "\r\n\x00") {
			r.errf(path, "логин и пароль не должны содержать переводы строк или нулевой байт")
		}
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
	if errS != nil || !start.Is4() {
		r.errf(path+".dhcp_pool.start", "некорректный адрес начала пула")
		return
	}
	if errE != nil || !end.Is4() {
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
	if start.Compare(prefix.Addr()) <= 0 && end.Compare(prefix.Addr()) >= 0 {
		r.errf(path+".dhcp_pool", "пул включает адрес самого роутера")
	}
	network := prefix.Masked().Addr()
	broadcast := ipv4Broadcast(prefix)
	if start.Compare(network) <= 0 || end.Compare(broadcast) >= 0 {
		r.errf(path+".dhcp_pool", "пул не должен включать адрес сети или широковещательный адрес")
	}
	if p.LeaseTime < 120 {
		r.warnf(path+".dhcp_pool.lease_time", "слишком короткое время аренды")
	}
	if p.LeaseTime < 1 || p.LeaseTime > 31_536_000 {
		r.errf(path+".dhcp_pool.lease_time", "время аренды должно быть от 1 секунды до 365 дней")
	}
	for i, raw := range p.DNSServers {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() {
			r.errf(fmt.Sprintf("%s.dhcp_pool.dns_servers[%d]", path, i), "нужен корректный IPv4-адрес DNS-сервера")
		}
	}
	if p.Gateway != "" {
		addr, err := netip.ParseAddr(p.Gateway)
		if err != nil || !addr.Is4() {
			r.errf(path+".dhcp_pool.gateway", "нужен корректный IPv4-адрес шлюза")
		} else if !prefix.Contains(addr) {
			r.errf(path+".dhcp_pool.gateway", "шлюз должен принадлежать подсети сегмента")
		}
	}
	if p.Domain != "" && !validDNSName(p.Domain) {
		r.errf(path+".dhcp_pool.domain", "нужно корректное DNS-имя домена")
	}
	for code, value := range p.Options {
		optionPath := path + ".dhcp_pool.options[" + strconv.Quote(code) + "]"
		n, err := strconv.Atoi(code)
		if err != nil || n < 1 || n > 254 {
			r.errf(optionPath, "код DHCP-опции должен быть числом от 1 до 254")
		}
		if unsafeConfigText(value) {
			r.errf(optionPath, "переводы строк и управляющие символы недопустимы")
		}
	}
}

func ipv4Broadcast(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As4()
	network := binary.BigEndian.Uint32(bytes[:])
	bits := prefix.Bits()
	var hostMask uint32
	if bits == 0 {
		hostMask = ^uint32(0)
	} else {
		hostMask = ^uint32(0) >> bits
	}
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], network|hostMask)
	return netip.AddrFrom4(out)
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
		if w.MTU != 0 && (w.MTU < 576 || w.MTU > 9216) {
			r.errf(path+".mtu", "MTU вне разумного диапазона 576-9216")
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
			} else if net.ParseIP(w.Server) == nil && !validDNSName(w.Server) {
				r.errf(path+".server", "укажите корректный IP-адрес или DNS-имя сервера L2TP")
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
			if err != nil || !validProbeHost(host) || !inPortRange(port) {
				r.errf(targetPath, "цель TCP должна быть в формате host:port")
			}
		case "http":
			parsed, err := url.ParseRequestURI(target)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
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

func validProbeHost(value string) bool {
	if value == "" || unsafeConfigText(value) {
		return false
	}
	if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return true
	}
	return validDNSName(value)
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

	// routeKeys — уже занятые сочетания «назначение + таблица + метрика».
	routeKeys := map[string]string{}
	for i, route := range c.Routing.Static {
		path := fmt.Sprintf("routing.static[%d]", i)
		switch route.Type {
		case "", "unicast", "blackhole", "unreachable", "prohibit":
		default:
			r.errf(path+".type", "неизвестный тип маршрута %q", route.Type)
		}
		if route.Destination != "default" {
			if _, err := netip.ParsePrefix(route.Destination); err != nil {
				if _, err := netip.ParseAddr(route.Destination); err != nil {
					r.errf(path+".destination", "ожидается подсеть, адрес или слово default")
				}
			}
		}
		if route.Gateway != "" {
			gateway, err := netip.ParseAddr(route.Gateway)
			if err != nil {
				r.errf(path+".gateway", "некорректный адрес шлюза")
			} else if destinationFamily, ok := routeDestinationFamily(route.Destination); ok && destinationFamily != gateway.Is6() {
				r.errf(path+".gateway", "семейство адреса шлюза должно совпадать с назначением маршрута")
			}
		}
		if route.Gateway == "" && route.Interface == "" && route.Type == "" {
			r.errf(path, "укажите шлюз, интерфейс или тип маршрута")
		}
		if route.Interface != "" && !ValidInterfaceName(route.Interface) {
			r.errf(path+".interface", "некорректное имя интерфейса")
		}
		if route.Metric < 0 {
			r.errf(path+".metric", "метрика не может быть отрицательной")
		}
		if route.Table != "" && !tables[route.Table] {
			r.errf(path+".table", "неизвестная таблица %q", route.Table)
		}
		// Назначение, таблица и метрика — это и есть адрес маршрута в ядре.
		// Два включённых маршрута с одинаковым адресом ядро не хранит: второй
		// вытесняет первый молча, панель продолжает показывать оба, а проверка
		// после применения расхождения не видит. Отвергаем на входе.
		if !route.Enabled {
			continue
		}
		key := fmt.Sprintf("%s\x00%s\x00%d", route.Destination, route.Table, route.Metric)
		if prev, taken := routeKeys[key]; taken {
			table := route.Table
			if table == "" {
				table = "main"
			}
			r.errf(path+".destination",
				"маршрут до %s в таблице %s с метрикой %d уже описан правилом %q: ядро оставит только один из них",
				route.Destination, table, route.Metric, prev)
		}
		name := route.Name
		if name == "" {
			name = fmt.Sprintf("№%d", i+1)
		}
		routeKeys[key] = name
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
		if rule.FwMark != "" && !validFwMark(rule.FwMark) {
			r.errf(path+".fwmark", "метка должна быть 32-битным числом, при необходимости с маской: например 0x10/0xff")
		}
		if rule.Interface != "" && !ValidInterfaceName(rule.Interface) {
			r.errf(path+".interface", "некорректное имя входного интерфейса")
		}
	}
}

func routeDestinationFamily(destination string) (is6 bool, ok bool) {
	if prefix, err := netip.ParsePrefix(destination); err == nil {
		return prefix.Addr().Is6(), true
	}
	if addr, err := netip.ParseAddr(destination); err == nil {
		return addr.Is6(), true
	}
	return false, false
}

func validFwMark(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 0, 32); err != nil {
			return false
		}
	}
	return true
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
		switch rule.Protocol {
		case "", "any", "tcp", "udp", "icmp":
		default:
			r.errf(path+".protocol", "неподдерживаемый протокол %q", rule.Protocol)
		}
		if rule.Interface != "" && !ValidInterfaceName(rule.Interface) {
			r.errf(path+".interface", "некорректное имя интерфейса")
		}
		if rule.ConnState != "" {
			allowedStates := map[string]bool{"new": true, "established": true, "related": true, "invalid": true}
			seenStates := map[string]bool{}
			for _, state := range strings.Split(strings.ToLower(rule.ConnState), ",") {
				state = strings.TrimSpace(state)
				if !allowedStates[state] || seenStates[state] {
					r.errf(path+".conn_state", "состояния соединения: new, established, related, invalid; без повторов")
					break
				}
				seenStates[state] = true
			}
		}
		validateSchedule(r, path+".schedule", rule.Schedule)
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
			} else if !ValidInterfaceName(n.Interface) {
				r.errf(path+".interface", "некорректное имя интерфейса")
			} else if !ifaceNames[n.Interface] {
				r.warnf(path+".interface", "интерфейс %q не описан в конфигурации", n.Interface)
			}
			validateCIDR(r, path+".source", n.Source)
			if n.ToSource != "" {
				if addr, err := netip.ParseAddr(n.ToSource); err != nil || !addr.Is4() {
					r.errf(path+".to_source", "некорректный адрес подмены")
				}
			}
		case "destination":
			if n.Interface != "" {
				if !ValidInterfaceName(n.Interface) {
					r.errf(path+".interface", "некорректное имя интерфейса")
				} else if !ifaceNames[n.Interface] {
					r.warnf(path+".interface", "интерфейс %q не описан в конфигурации", n.Interface)
				}
			}
			if n.Protocol != "tcp" && n.Protocol != "udp" && n.Protocol != "tcpudp" {
				r.errf(path+".protocol", "протокол должен быть tcp, udp или tcpudp")
			}
			validateNATPortSpec(r, path+".ext_port", n.ExtPort, true)
			validateNATPortSpec(r, path+".dest_port", n.DestPort, false)
			if addr, err := netip.ParseAddr(n.DestIP); err != nil || !addr.Is4() {
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
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("порт вне диапазона 1-65535")
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
	if c.DHCP.AdvancedOptions != "" && c.DHCP.Provider == "kea" {
		r.errf("dhcp.advanced_options", "Kea использует структурированный JSON и не поддерживает произвольные текстовые директивы")
	}

	networks := c.networkIDs()
	seenMAC := map[string]bool{}
	seenIP := map[string]bool{}
	seenID := map[string]bool{}

	for i, res := range c.DHCP.Reservations {
		path := fmt.Sprintf("dhcp.reservations[%d]", i)
		if res.ID == "" || seenID[res.ID] {
			r.errf(path+".id", "пустой или повторяющийся идентификатор привязки")
		}
		seenID[res.ID] = true
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
		if err != nil || !addr.Is4() {
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
		if res.Hostname != "" && !validDNSName(res.Hostname) {
			r.errf(path+".hostname", "имя устройства должно быть корректным DNS-именем")
		}
	}
}

func (c *Config) validateDNS(r *ValidationResult) {
	if c.DNS.Provider != "" {
		switch c.DNS.Provider {
		case "dnsmasq", "unbound", "dnsproxy":
		default:
			r.errf("dns.provider", "неизвестный резолвер %q", c.DNS.Provider)
		}
	}
	if c.DNS.DNSSEC && c.DNS.Enabled && c.DNS.Provider == "dnsmasq" {
		r.errf("dns.dnssec", "проверка DNSSEC для dnsmasq в netOS не реализована — выберите unbound или dnsproxy")
	}
	if c.DNS.AdvancedOptions != "" && c.DNS.Provider != "unbound" {
		r.errf("dns.advanced_options", "произвольные DNS-директивы поддерживаются только провайдером unbound")
	}
	if c.DNS.Port < 1 || c.DNS.Port > 65535 {
		r.errf("dns.port", "порт DNS вне диапазона 1-65535")
	}
	if c.DNS.CacheSize < 0 || c.DNS.CacheSize > 1_000_000 {
		r.errf("dns.cache_size", "размер кэша должен быть от 0 до 1000000 записей")
	}
	if c.DNS.LocalDomain != "" && !validDNSName(c.DNS.LocalDomain) {
		r.errf("dns.local_domain", "нужно корректное DNS-имя локального домена")
	}
	for i, raw := range c.DNS.Bootstrap {
		if err := validateDNSBootstrap(raw); err != nil {
			r.errf(fmt.Sprintf("dns.bootstrap[%d]", i), "%v", err)
		}
	}

	channels := c.usableChannelIDs()
	upstreams := map[string]bool{}
	upstreamByID := map[string]Upstream{}
	channelOwner := map[string]string{}
	secure := 0
	upstreamIDs := map[string]bool{}
	unboundHasPlain := false
	unboundHasDoT := false

	for i, u := range c.DNS.Upstreams {
		path := fmt.Sprintf("dns.upstreams[%d]", i)
		if u.ID == "" || upstreamIDs[u.ID] {
			r.errf(path+".id", "пустой или повторяющийся идентификатор апстрима")
		}
		upstreamIDs[u.ID] = true
		upstreams[u.ID] = true
		upstreamByID[u.ID] = u
		switch u.Type {
		case "plain":
			if u.Enabled {
				unboundHasPlain = true
			}
		case "dot", "doh", "doq":
			if u.Enabled {
				secure++
				if u.Type == "dot" {
					unboundHasDoT = true
				}
			}
			if c.DNS.Enabled && c.DNS.Provider == "dnsmasq" {
				r.errf(path+".type",
					"dnsmasq не умеет %s — выберите unbound или dnsproxy",
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
		} else if err := validateDNSUpstreamAddress(c.DNS.Provider, u); err != nil {
			r.errf(path+".address", "%v", err)
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
	if c.DNS.Enabled && c.DNS.Provider == "unbound" && unboundHasPlain && unboundHasDoT {
		r.errf("dns.upstreams", "unbound не поддерживает одновременное использование открытых DNS и DoT-апстримов: выберите один тип для всех включённых серверов")
	}

	recordIDs := map[string]bool{}
	for i, record := range c.DNS.StaticRecords {
		path := fmt.Sprintf("dns.static_records[%d]", i)
		if record.ID == "" || recordIDs[record.ID] {
			r.errf(path+".id", "пустой или повторяющийся идентификатор записи")
		}
		recordIDs[record.ID] = true
		validateDNSRecord(r, path, record)
		if c.DNS.Enabled && c.DNS.Provider == "dnsproxy" && record.Type != "A" {
			r.errf(path+".type", "dnsproxy поддерживает локально только A-записи; выберите dnsmasq или unbound")
		}
		if c.DNS.Enabled && c.DNS.Provider == "dnsmasq" && record.Type == "TXT" && strings.Contains(record.Value, ",") {
			r.errf(path+".value", "TXT-запись dnsmasq не должна содержать запятые")
		}
	}

	if secure > 0 && len(c.DNS.Bootstrap) == 0 {
		r.warnf("dns.bootstrap",
			"для шифрованного DNS нужен обычный резолвер, чтобы разрешить имя самого сервера")
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
	// dnsproxy умеет только классифицировать приватные сети для обратных
	// запросов; отбрасывать ответы публичного DNS, указывающие внутрь локальной
	// сети, он не умеет вовсе. Молча оставленный включённым переключатель здесь
	// хуже отсутствующего: администратор видит защиту, которой нет.
	if c.DNS.Enabled && c.DNS.Provider == "dnsproxy" && c.DNS.RebindProtection {
		r.warnf("dns.rebind_protection",
			"dnsproxy не отбрасывает ответы с приватными адресами: защита от DNS rebinding работать не будет — выберите dnsmasq или unbound")
	}

	if c.DNS.Enabled && c.DNS.Provider != "dnsmasq" &&
		c.DHCP.Enabled && c.DHCP.Provider != "dnsmasq" {
		r.warnf("dhcp.provider",
			"имена клиентов, выданные по DHCP, разрешаться не будут: отдать их резолверу умеет только dnsmasq — выберите его сервером DHCP или задавайте имена вручную в записях DNS")
	}

	splitIDs := map[string]bool{}
	for i, rule := range c.DNS.SplitRules {
		path := fmt.Sprintf("dns.split_rules[%d]", i)
		if rule.ID == "" || splitIDs[rule.ID] {
			r.errf(path+".id", "пустой или повторяющийся идентификатор правила")
		}
		splitIDs[rule.ID] = true
		if len(rule.Domains) == 0 {
			r.errf(path+".domains", "правило без доменов")
		}
		seenDomains := map[string]bool{}
		for j, raw := range rule.Domains {
			domain := strings.Trim(raw, ".")
			domainPath := fmt.Sprintf("%s.domains[%d]", path, j)
			if domain == "" || !validDNSName(domain) || unsafeConfigText(raw) {
				r.errf(domainPath, "нужно корректное DNS-имя домена")
			} else if seenDomains[strings.ToLower(domain)] {
				r.errf(domainPath, "домен уже указан в этом правиле")
			}
			seenDomains[strings.ToLower(domain)] = true
		}
		if rule.Upstream != "" && !upstreams[rule.Upstream] {
			r.errf(path+".upstream", "неизвестный апстрим %q", rule.Upstream)
		} else if rule.Enabled && rule.Upstream != "" && !upstreamByID[rule.Upstream].Enabled {
			r.errf(path+".upstream", "выбранный апстрим выключен")
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
	blocklistURLs := map[string]int{}
	for i, blocklist := range c.DNS.Blocklists {
		path := fmt.Sprintf("dns.blocklists[%d]", i)
		if unsafeConfigText(blocklist.Name) {
			r.errf(path+".name", "переводы строк и управляющие символы недопустимы")
		}
		if blocklist.Enabled && strings.TrimSpace(blocklist.Name) == "" {
			r.errf(path+".name", "укажите название списка блокировки")
		}
		if blocklist.Enabled && !c.DNS.Enabled {
			r.errf(path+".enabled", "нельзя включить список блокировки при выключенном DNS")
		}
		if blocklist.URL == "" {
			if blocklist.Enabled {
				r.errf(path+".url", "укажите HTTPS URL списка блокировки")
			}
			continue
		}
		parsed, err := url.Parse(blocklist.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || unsafeConfigText(blocklist.URL) {
			r.errf(path+".url", "нужен безопасный HTTPS URL без учётных данных и фрагмента")
			continue
		}
		canonical := parsed.String()
		if previous, exists := blocklistURLs[canonical]; exists {
			r.errf(path+".url", "этот URL уже используется списком %d", previous+1)
		} else {
			blocklistURLs[canonical] = i
		}
	}
}

func unsafeConfigText(value string) bool {
	if strings.TrimSpace(value) != value {
		return true
	}
	for _, ch := range value {
		if ch == 0 || ch == '\r' || ch == '\n' || ch < 0x20 || ch == 0x7f {
			return true
		}
	}
	return false
}

func validateDNSBootstrap(raw string) error {
	if raw == "" || unsafeConfigText(raw) {
		return fmt.Errorf("нужен буквальный IPv4-адрес bootstrap-сервера")
	}
	host, port := raw, ""
	if h, p, err := net.SplitHostPort(raw); err == nil {
		if p == "" {
			return fmt.Errorf("порт bootstrap-сервера не указан")
		}
		host, port = h, p
	} else if strings.Count(raw, ":") > 0 {
		return fmt.Errorf("bootstrap-сервер нужно указать как IPv4 или IPv4:порт")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("нужен буквальный IPv4-адрес bootstrap-сервера")
	}
	if port != "" && !inPortRange(port) {
		return fmt.Errorf("порт bootstrap-сервера вне диапазона 1-65535")
	}
	return nil
}

func validDNSHost(value string) bool {
	if addr, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return addr.Is4()
	}
	return validDNSName(value)
}

func validateDNSUpstreamAddress(provider string, up Upstream) error {
	raw := up.Address
	if unsafeConfigText(raw) || strings.ContainsAny(raw, "\"'\\") {
		return fmt.Errorf("адрес содержит недопустимые символы")
	}
	if provider == "dnsmasq" {
		if up.Type != "plain" {
			return nil // несовместимость типа сообщается отдельно
		}
		if strings.Contains(raw, "://") || strings.Contains(raw, "@") {
			return fmt.Errorf("для dnsmasq используйте адрес вида 1.1.1.1 или 1.1.1.1#5353")
		}
		host, port, found := strings.Cut(raw, "#")
		if !validDNSHost(host) || (found && !inPortRange(port)) || strings.Contains(port, "#") {
			return fmt.Errorf("некорректный адрес DNS-сервера")
		}
		return nil
	}
	if provider == "unbound" {
		if strings.Contains(raw, "://") {
			return fmt.Errorf("для unbound используйте адрес вида 1.1.1.1@853#dns.example")
		}
		endpoint, tlsName, hasTLSName := strings.Cut(raw, "#")
		host, port, hasPort := strings.Cut(endpoint, "@")
		if !validDNSHost(host) || (hasPort && !inPortRange(port)) || strings.Contains(port, "@") {
			return fmt.Errorf("некорректный адрес DNS-сервера")
		}
		if hasTLSName && !validDNSName(tlsName) {
			return fmt.Errorf("некорректное имя сервера для проверки TLS")
		}
		return nil
	}

	// dnsproxy accepts URI endpoints; the short form is normalized by the renderer.
	value := raw
	if !strings.Contains(value, "://") {
		scheme := map[string]string{"plain": "udp", "dot": "tls", "doh": "https", "doq": "quic"}[up.Type]
		value = scheme + "://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("некорректный адрес DNS-сервера")
	}
	allowed := map[string]map[string]bool{
		"plain": {"udp": true, "tcp": true}, "dot": {"tls": true},
		"doh": {"https": true}, "doq": {"quic": true},
	}
	if !allowed[up.Type][strings.ToLower(parsed.Scheme)] {
		return fmt.Errorf("схема адреса не соответствует типу апстрима %s", strings.ToUpper(up.Type))
	}
	if !validDNSHost(parsed.Hostname()) {
		return fmt.Errorf("некорректное имя или адрес DNS-сервера")
	}
	if parsed.Port() != "" && !inPortRange(parsed.Port()) {
		return fmt.Errorf("порт DNS-сервера вне диапазона 1-65535")
	}
	if up.Type == "doh" && parsed.Path == "" {
		return fmt.Errorf("для DoH нужен полный HTTPS URL с путём запроса")
	}
	return nil
}

func validDNSRecordName(value string, allowUnderscore bool) bool {
	if !allowUnderscore {
		return validDNSName(value)
	}
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		trimmed := strings.TrimPrefix(label, "_")
		if trimmed == "" || !validDNSName(trimmed) {
			return false
		}
	}
	return true
}

func validateUintField(value string, min, max int) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n >= min && n <= max
}

func validateDNSRecord(r *ValidationResult, path string, record DNSRecord) {
	if unsafeConfigText(record.Name) || !validDNSRecordName(record.Name, record.Type == "SRV") {
		r.errf(path+".name", "некорректное имя DNS-записи")
	}
	if unsafeConfigText(record.Value) {
		r.errf(path+".value", "переводы строк и управляющие символы недопустимы")
		return
	}
	switch record.Type {
	case "A":
		addr, err := netip.ParseAddr(record.Value)
		if err != nil || !addr.Is4() {
			r.errf(path+".value", "для A-записи нужен IPv4-адрес")
		}
	case "CNAME":
		if !validDNSName(strings.TrimSuffix(record.Value, ".")) {
			r.errf(path+".value", "для CNAME нужно корректное DNS-имя")
		}
	case "TXT":
		if record.Value == "" || len(record.Value) > 255 {
			r.errf(path+".value", "TXT-значение должно содержать от 1 до 255 байт")
		}
	case "SRV":
		fields := strings.Fields(record.Value)
		if len(fields) != 4 || !validateUintField(fields[0], 0, 65535) ||
			!validateUintField(fields[1], 0, 65535) || !validateUintField(fields[2], 1, 65535) ||
			!validDNSName(strings.TrimSuffix(fields[3], ".")) {
			r.errf(path+".value", "SRV задаётся как: приоритет вес порт имя-сервера")
		}
	case "MX":
		fields := strings.Fields(record.Value)
		if len(fields) != 2 || !validateUintField(fields[0], 0, 65535) || !validDNSName(strings.TrimSuffix(fields[1], ".")) {
			r.errf(path+".value", "MX задаётся как: приоритет имя-почтового-сервера")
		}
	default:
		r.errf(path+".type", "неподдерживаемый тип DNS-записи %q", record.Type)
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
		if len(p.Domains) > 128 {
			r.errf(path+".domains", "в одной политике допускается не больше 128 доменов")
		}
		seenDomains := map[string]bool{}
		for j, raw := range p.Domains {
			domainPath := fmt.Sprintf("%s.domains[%d]", path, j)
			domain := strings.Trim(raw, ".")
			canonical := strings.ToLower(domain)
			if domain == "" || unsafeConfigText(raw) || !validDNSName(domain) {
				r.errf(domainPath, "нужно корректное DNS-имя без пробелов и управляющих символов")
			} else if seenDomains[canonical] {
				r.errf(domainPath, "домен уже указан в этой политике")
			}
			seenDomains[canonical] = true
		}
		if p.Enabled && len(p.Domains) > 0 && serverTypes[p.VPNServer] != "xray" {
			if !c.DNS.Enabled {
				r.errf(path+".domains", "для доменной политики включите DNS-резолвер netOS")
			} else if !c.IPv6.FilterAAAA {
				r.errf(path+".domains", "доменная политика каналов поддерживает IPv4: включите фильтрацию AAAA")
			} else if c.DNS.Provider != "dnsmasq" && c.DNS.Port == 5355 {
				r.errf("dns.port", "порт 5355 занят внутренним DNS backend доменных политик")
			}
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
		validateSchedule(r, path+".schedule", p.Schedule)
		if p.SrcIP == "" && p.SrcMAC == "" && p.Network == "" && p.VPNServer == "" &&
			p.DstIP == "" && p.DstPort == "" && len(p.Domains) == 0 {
			r.warnf(path, "политика без единого условия перехватит весь трафик")
		}
	}
}

func validateSchedule(r *ValidationResult, path string, schedule *Schedule) {
	if schedule == nil {
		return
	}
	allowedDays := map[string]bool{"Mon": true, "Tue": true, "Wed": true, "Thu": true, "Fri": true, "Sat": true, "Sun": true}
	seen := map[string]bool{}
	for i, day := range schedule.Days {
		if !allowedDays[day] || seen[day] {
			r.errf(fmt.Sprintf("%s.days[%d]", path, i), "день должен быть Mon, Tue, Wed, Thu, Fri, Sat или Sun и не повторяться")
		}
		seen[day] = true
	}
	for field, value := range map[string]string{"time_start": schedule.TimeStart, "time_stop": schedule.TimeStop} {
		if value == "" {
			continue
		}
		valid := false
		if len(value) == 5 && value[2] == ':' {
			_, err := time.Parse("15:04", value)
			valid = err == nil
		} else if len(value) == 8 && value[2] == ':' && value[5] == ':' {
			_, err := time.Parse("15:04:05", value)
			valid = err == nil
		}
		if !valid {
			r.errf(path+"."+field, "время должно быть в формате ЧЧ:ММ или ЧЧ:ММ:СС")
		}
	}
}

func (c *Config) validateVPNServers(r *ValidationResult) {
	channels := c.usableChannelIDs()
	ports := map[string]string{fmt.Sprintf("tcp/%d", c.System.Panel.Port): "веб-панель"}
	if c.DNS.Enabled {
		ports[fmt.Sprintf("tcp/%d", c.DNS.Port)] = "DNS"
		ports[fmt.Sprintf("udp/%d", c.DNS.Port)] = "DNS"
	}
	claimPort := func(path, protocol string, port int, owner string) {
		key := fmt.Sprintf("%s/%d", protocol, port)
		if previous := ports[key]; previous != "" {
			r.errf(path, "%s-порт %d уже занят: %s", strings.ToUpper(protocol), port, previous)
			return
		}
		ports[key] = owner
	}
	ids := map[string]bool{}
	indexes := map[int]bool{}
	for i, s := range c.VPNServers {
		path := fmt.Sprintf("vpn_servers[%d]", i)
		if s.Name == "" || unsafeConfigText(s.Name) {
			r.errf(path+".name", "название не должно быть пустым или содержать управляющие символы")
		}
		if s.ID == "" || ids[s.ID] {
			r.errf(path+".id", "пустой или повторяющийся идентификатор VPN-сервера")
		}
		ids[s.ID] = true
		if s.Index < 1 || s.Index > 9999 || indexes[s.Index] {
			r.errf(path+".index", "индекс VPN-сервера должен быть уникальным числом 1-9999")
		}
		indexes[s.Index] = true
		if s.Enabled && s.Type != "wireguard" && s.Type != "xray" && s.Type != "ocserv" && s.Type != "ikev2" {
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
		} else {
			if subnet.Bits() > 30 {
				r.errf(path+".subnet", "в VPN-подсети должно быть место для сервера и хотя бы одного клиента")
			}
			if subnet.Addr() == subnet.Masked().Addr() || subnet.Addr() == ipv4Broadcast(subnet) {
				r.errf(path+".subnet", "укажите адрес VPN-сервера в подсети, а не адрес сети или broadcast")
			}
		}
		if s.Enabled {
			switch s.Type {
			case "wireguard":
				claimPort(path+".port", "udp", s.Port, fmt.Sprintf("VPN-сервер %q", s.Name))
			case "xray":
				claimPort(path+".port", "tcp", s.Port, fmt.Sprintf("VPN-сервер %q", s.Name))
			case "ocserv":
				claimPort(path+".port", "tcp", s.Port, fmt.Sprintf("VPN-сервер %q", s.Name))
				claimPort(path+".port", "udp", s.Port, fmt.Sprintf("VPN-сервер %q", s.Name))
			case "ikev2":
				claimPort(path+".port", "udp", 500, fmt.Sprintf("IKEv2-сервер %q", s.Name))
				claimPort(path+".port", "udp", 4500, fmt.Sprintf("IKEv2-сервер %q", s.Name))
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
		if s.Type == "ocserv" {
			c.validateOcservServer(r, path, s)
		}
		if s.Type == "ikev2" {
			c.validateIKEv2Server(r, path, s)
		}

		seenAddr := map[string]bool{}
		seenPeerIDs := map[string]bool{}
		for j, peer := range s.Peers {
			ppath := fmt.Sprintf("%s.peers[%d]", path, j)
			if peer.ID == "" || seenPeerIDs[peer.ID] {
				r.errf(ppath+".id", "пустой или повторяющийся идентификатор клиента")
			}
			seenPeerIDs[peer.ID] = true
			addr, err := netip.ParseAddr(peer.Address)
			if err != nil || !addr.Is4() {
				r.errf(ppath+".address", "некорректный адрес")
				continue
			}
			if subnet.IsValid() && !subnet.Contains(addr) {
				r.errf(ppath+".address", "адрес вне подсети сервера %s", s.Subnet)
			} else if subnet.IsValid() && (addr == subnet.Addr() || addr == subnet.Masked().Addr() || addr == ipv4Broadcast(subnet)) {
				r.errf(ppath+".address", "клиенту нельзя назначить адрес сервера, сети или broadcast")
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

func (c *Config) validateIKEv2Server(r *ValidationResult, path string, s VPNServer) {
	ike, err := s.IKEv2Config()
	if err != nil {
		r.errf(path+".config", "%v", err)
		return
	}
	if !s.Enabled {
		return
	}
	// IKEv2 always uses the standard UDP ports, independently of the generic
	// port field retained in the common data model.
	if s.Port != 0 && s.Port != 500 {
		r.errf(path+".port", "IKEv2 использует стандартные UDP-порты 500 и 4500")
	}
	if ike.PublicEndpoint != "" && net.ParseIP(ike.PublicEndpoint) == nil && !validDNSName(ike.PublicEndpoint) {
		r.errf(path+".config.public_endpoint", "укажите доменное имя или IP-адрес без порта")
	}
	identity := ike.ServerIdentity
	if identity == "" {
		identity = ike.PublicEndpoint
	}
	if identity == "" || !validDNSHost(identity) {
		r.errf(path+".config.server_identity", "укажите безопасное имя сервера, совпадающее с сертификатом")
	}
	if ike.MTU != 0 && (ike.MTU < 1280 || ike.MTU > 9000) {
		r.errf(path+".config.mtu", "MTU вне диапазона 1280-9000")
	}
	for i, address := range ike.DNS {
		if ip := net.ParseIP(address); ip == nil || ip.To4() == nil {
			r.errf(fmt.Sprintf("%s.config.dns[%d]", path, i), "некорректный IPv4-адрес DNS")
		}
	}
	for i, route := range ike.SplitRoutes {
		if prefix, err := netip.ParsePrefix(route); err != nil || !prefix.Addr().Is4() {
			r.errf(fmt.Sprintf("%s.config.split_routes[%d]", path, i), "некорректная IPv4-подсеть")
		}
	}
	usernames := map[string]bool{}
	enabledPeers := 0
	for i, peer := range s.Peers {
		if peer.Enabled {
			enabledPeers++
			if enabledPeers > 1 {
				r.errf(fmt.Sprintf("%s.peers[%d].enabled", path, i), "в Debian strongSwan нельзя надёжно закрепить адрес за EAP-учётной записью; одновременно разрешён только один пользователь IKEv2")
			}
		}
		username := peer.Credentials["username"]
		if username == "" || !safeAccountName(username) {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.username", path, i), "имя пользователя может содержать только буквы, цифры, точку, дефис и подчёркивание")
		}
		if usernames[username] {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.username", path, i), "имя пользователя уже используется")
		}
		usernames[username] = true
		if peer.Enabled && len(peer.Credentials["password"]) < 8 {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.password", path, i), "пароль должен содержать не меньше 8 символов")
		}
		if unsafeConfigText(peer.Credentials["password"]) {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.password", path, i), "пароль не должен содержать управляющие символы")
		}
	}
}

func (c *Config) validateOcservServer(r *ValidationResult, path string, s VPNServer) {
	oc, err := s.OcservConfig()
	if err != nil {
		r.errf(path+".config", "%v", err)
		return
	}
	if !s.Enabled {
		return
	}
	if s.Port < 1 || s.Port > 65535 {
		r.errf(path+".port", "порт должен быть в диапазоне 1-65535")
	}
	if oc.PublicEndpoint != "" {
		if host, port, err := net.SplitHostPort(oc.PublicEndpoint); err != nil || !validDNSHost(host) || !inPortRange(port) {
			r.errf(path+".config.public_endpoint", "публичный адрес должен быть в формате vpn.example.com:443")
		}
	}
	if oc.MTU != 0 && (oc.MTU < 576 || oc.MTU > 9000) {
		r.errf(path+".config.mtu", "MTU вне диапазона 576-9000")
	}
	if strings.ContainsAny(oc.Banner, "\r\n\x00") {
		r.errf(path+".config.banner", "переводы строк и нулевой байт недопустимы")
	}
	for i, address := range oc.DNS {
		if ip := net.ParseIP(address); ip == nil || ip.To4() == nil {
			r.errf(fmt.Sprintf("%s.config.dns[%d]", path, i), "некорректный IPv4-адрес DNS")
		}
	}
	for i, route := range oc.Routes {
		if prefix, err := netip.ParsePrefix(route); err != nil || !prefix.Addr().Is4() {
			r.errf(fmt.Sprintf("%s.config.routes[%d]", path, i), "некорректная IPv4-подсеть")
		}
	}
	usernames := map[string]bool{}
	for i, peer := range s.Peers {
		username := peer.Credentials["username"]
		if username == "" || !safeAccountName(username) {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.username", path, i), "имя пользователя может содержать только буквы, цифры, точку, дефис и подчёркивание")
		}
		if usernames[username] {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.username", path, i), "имя пользователя уже используется")
		}
		usernames[username] = true
		if peer.Enabled && len(peer.Credentials["password"]) < 8 {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.password", path, i), "пароль должен содержать не меньше 8 символов")
		}
		if unsafeConfigText(peer.Credentials["password"]) {
			r.errf(fmt.Sprintf("%s.peers[%d].credentials.password", path, i), "пароль не должен содержать управляющие символы")
		}
	}
}

func safeAccountName(value string) bool {
	if value == "." || value == ".." || len(value) > 64 {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return value != ""
}

func validDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func safeObjectID(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 64 {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func validTimezone(value string) bool {
	if value == "" || len(value) > 128 || strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '/' || ch == '_' || ch == '+' || ch == '-' {
			continue
		}
		return false
	}
	return true
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
	if host, port, err := net.SplitHostPort(xr.Destination); err != nil || !validDNSHost(host) || !inPortRange(port) {
		r.errf(path+".config.destination", "цель маскировки должна быть в формате www.example.com:443")
	}
	if xr.PublicEndpoint != "" {
		if host, port, err := net.SplitHostPort(xr.PublicEndpoint); err != nil || !validDNSHost(host) || !inPortRange(port) {
			r.errf(path+".config.public_endpoint", "публичный адрес должен быть в формате vpn.example.com:443")
		}
	}
	if len(xr.ServerNames) == 0 {
		r.errf(path+".config.server_names", "укажите хотя бы одно имя сервера Reality")
	}
	serverNames := map[string]bool{}
	for i, name := range xr.ServerNames {
		if !validDNSName(name) {
			r.errf(fmt.Sprintf("%s.config.server_names[%d]", path, i), "некорректное DNS-имя Reality")
		} else if serverNames[strings.ToLower(name)] {
			r.errf(fmt.Sprintf("%s.config.server_names[%d]", path, i), "имя Reality указано повторно")
		}
		serverNames[strings.ToLower(name)] = true
	}
	if len(xr.ShortIDs) == 0 {
		r.errf(path+".config.short_ids", "укажите хотя бы один short ID Reality")
	}
	shortIDs := map[string]bool{}
	for i, id := range xr.ShortIDs {
		if len(id) == 0 || len(id) > 16 || len(id)%2 != 0 {
			r.errf(fmt.Sprintf("%s.config.short_ids[%d]", path, i), "short ID должен содержать чётное число hex-символов, не больше 16")
			continue
		}
		if _, err := hex.DecodeString(id); err != nil {
			r.errf(fmt.Sprintf("%s.config.short_ids[%d]", path, i), "short ID должен быть шестнадцатеричным")
		}
		if shortIDs[strings.ToLower(id)] {
			r.errf(fmt.Sprintf("%s.config.short_ids[%d]", path, i), "short ID указан повторно")
		}
		shortIDs[strings.ToLower(id)] = true
	}
	if xr.Flow != "" && xr.Flow != "xtls-rprx-vision" {
		r.errf(path+".config.flow", "поддерживается только поток xtls-rprx-vision")
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
		if host, port, err := net.SplitHostPort(wg.PublicEndpoint); err != nil || !validDNSHost(host) || !inPortRange(port) {
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
	enabledNetworks := map[string]bool{}
	for _, network := range c.Networks {
		enabledNetworks[network.ID] = network.Enabled
	}
	radioIDs := map[string]bool{}
	devices := map[string]bool{}
	for i, radio := range c.WiFi {
		path := fmt.Sprintf("wifi[%d]", i)
		if radio.ID == "" || radioIDs[radio.ID] {
			r.errf(path+".id", "пустой или повторяющийся идентификатор радио")
		}
		radioIDs[radio.ID] = true
		if radio.Device == "" {
			r.errf(path+".device", "не выбрано радиоустройство")
		} else if len(radio.Device) > 15 || strings.ContainsAny(radio.Device, " /\\\r\n\t") {
			r.errf(path+".device", "некорректное имя радиоустройства")
		} else if devices[radio.Device] {
			r.errf(path+".device", "радиоустройство уже используется")
		}
		devices[radio.Device] = true
		switch radio.Band {
		case "2.4":
			// The renderer always enables 802.11n, while channel 14 is an
			// 802.11b-only special case in Japan. Advertising it would produce a
			// hostapd configuration that cannot start.
			if radio.Channel < 1 || radio.Channel > 13 {
				r.errf(path+".channel", "для диапазона 2,4 ГГц нужен канал 1-13")
			}
		case "5":
			if !valid5GHzPrimaryChannel(radio.Channel) {
				r.errf(path+".channel", "нужен стандартный первичный канал 5 ГГц")
			}
		default:
			r.errf(path+".band", "поддерживаются диапазоны 2,4 и 5 ГГц")
		}
		if radio.Width != 20 && radio.Width != 40 && radio.Width != 80 {
			r.errf(path+".width", "поддерживается ширина канала 20, 40 или 80 МГц")
		}
		if radio.Band == "2.4" && radio.Width == 80 {
			r.errf(path+".width", "80 МГц недоступны в диапазоне 2,4 ГГц")
		}
		if radio.Band == "5" && radio.Width > 20 && !valid5GHzWidePrimaryChannel(radio.Channel) {
			r.errf(path+".channel", "для ширины 40/80 МГц выберите канал 36-161 из стандартного блока")
		}
		if len(radio.Country) != 2 || !asciiLetter(radio.Country[0]) || !asciiLetter(radio.Country[1]) {
			r.errf(path+".country", "нужен двухбуквенный код страны")
		}
		if radio.TxPower < 0 || radio.TxPower > 40 {
			r.errf(path+".tx_power", "мощность должна быть в диапазоне 0-40 dBm")
		}
		enabledSSIDs := 0
		ssidIDs := map[string]bool{}
		ssidNames := map[string]bool{}
		for _, ssid := range radio.SSIDs {
			if ssid.Enabled {
				enabledSSIDs++
			}
		}
		if enabledSSIDs > 1 {
			lastBSS := fmt.Sprintf("%s-n%d", radio.Device, enabledSSIDs-1)
			if len(lastBSS) > 15 {
				r.errf(path+".device", "имя устройства слишком длинное для %d Wi-Fi-сетей", enabledSSIDs)
			}
		}
		if radio.Enabled && enabledSSIDs == 0 {
			r.errf(path+".ssids", "включите хотя бы одну Wi-Fi-сеть")
		}
		for j, s := range radio.SSIDs {
			spath := fmt.Sprintf("%s.ssids[%d]", path, j)
			if s.ID == "" || ssidIDs[s.ID] {
				r.errf(spath+".id", "пустой или повторяющийся идентификатор сети")
			}
			ssidIDs[s.ID] = true
			if s.SSID == "" {
				r.errf(spath+".ssid", "пустое имя сети")
			}
			if len([]byte(s.SSID)) > 32 {
				r.errf(spath+".ssid", "имя сети длиннее 32 байт")
			}
			if strings.ContainsAny(s.SSID, "\r\n\x00") || strings.ContainsAny(s.Password, "\r\n\x00") {
				r.errf(spath, "переводы строк и нулевой байт недопустимы")
			}
			if s.Enabled && ssidNames[s.SSID] {
				r.errf(spath+".ssid", "это имя сети уже используется на радио")
			}
			if s.Enabled {
				ssidNames[s.SSID] = true
			}
			if !networks[s.Network] {
				r.errf(spath+".network", "неизвестный сегмент %q", s.Network)
			} else if s.Enabled && !enabledNetworks[s.Network] {
				r.errf(spath+".network", "сегмент %q выключен", s.Network)
			}
			switch s.Security {
			case "open":
				if s.Enabled {
					r.warnf(spath+".security", "открытая сеть без шифрования")
				}
			case "wpa2", "wpa3", "wpa2/wpa3":
				if s.Enabled && (len(s.Password) < 8 || len(s.Password) > 63) {
					r.errf(spath+".password", "пароль должен содержать 8-63 символа")
				}
			default:
				r.errf(spath+".security", "неизвестный режим безопасности %q", s.Security)
			}
		}
	}
}

func asciiLetter(ch byte) bool {
	return ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

func valid5GHzPrimaryChannel(channel int) bool {
	for _, candidate := range []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177} {
		if channel == candidate {
			return true
		}
	}
	return false
}

func valid5GHzWidePrimaryChannel(channel int) bool {
	return valid5GHzPrimaryChannel(channel) && channel <= 161
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
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() {
		return
	}
	if addr, err := netip.ParseAddr(value); err == nil && addr.Is4() {
		return
	}
	r.errf(path, "ожидается IPv4-адрес или подсеть, получено %q", value)
}

func validatePortSpec(r *ValidationResult, path, value string) {
	if value == "" {
		return
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		if !inPortRange(lo) || (isRange && (!inPortRange(hi) || portNumber(lo) > portNumber(hi))) {
			r.errf(path, "некорректная спецификация порта %q", value)
			return
		}
	}
}

func validateNATPortSpec(r *ValidationResult, path, value string, required bool) {
	if value == "" {
		if required {
			r.errf(path, "укажите внешний порт или диапазон портов")
		}
		return
	}
	if strings.Contains(value, ",") {
		r.errf(path, "для NAT укажите один порт или один диапазон без списка")
		return
	}
	validatePortSpec(r, path, value)
}

func portNumber(value string) int {
	n, _ := strconv.Atoi(value)
	return n
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

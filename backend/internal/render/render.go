// Package render — каталог сгенерированных артефактов: что netOS кладёт на
// машину и во что превращается конфигурация.
//
// Каталог один на всех потребителей: `netos render`, `netosd -render` и
// раздел «Диагностика» в панели. Раньше список был у каждого свой, и они
// разошлись: CLI печатал десяток артефактов, а панель показывала жёстко
// зашитый конфиг dnsmasq — в том числе когда dnsmasq выключен, а работают
// unbound и ISC DHCP. Администратор при этом видел конфигурацию демона,
// которого на машине нет, вместо конфигурации того, который работает.
//
// Поэтому у каждого артефакта есть Active: он сообщает, участвует ли артефакт
// в текущей конфигурации. Панель показывает только участвующие.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/firewall"
	"github.com/netos-router/netos/internal/subsys/netconf"
	"github.com/netos-router/netos/internal/subsys/services"
	"github.com/netos-router/netos/internal/subsys/sysctl"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/subsys/wifi"
)

// Artifact — один сгенерированный файл или набор правил.
type Artifact struct {
	// ID — имя для `netos render <id>` и для запроса из панели.
	ID string
	// Title — как артефакт называется в панели.
	Title string
	// Active сообщает, работает ли этот артефакт при такой конфигурации.
	Active func(cfg *config.Config) bool
	// Render собирает содержимое.
	Render func(cfg *config.Config) (string, error)
}

// always — артефакты, которые netOS кладёт на любую машину.
func always(*config.Config) bool { return true }

// Предикаты берутся у самих подсистем, а не пишутся здесь заново: демон и
// артефакт обязаны включаться по одному и тому же условию. Раннер им не
// нужен — Needed смотрит только в конфигурацию.
var (
	dnsmasq  = services.NewDnsmasq(nil)
	isc      = services.NewISCDHCP(nil)
	kea      = services.NewKeaDHCP(nil)
	unbound  = services.NewUnbound(nil)
	dnsproxy = services.NewDnsproxy(nil)
	resolv   = services.NewSystemResolver(nil)
)

func wireGuardActive(cfg *config.Config) bool {
	for _, ch := range cfg.Channels {
		if ch.Enabled && ch.Type == "wireguard" {
			return true
		}
	}
	return false
}

func renderWireGuard(cfg *config.Config) (string, error) {
	var b bytes.Buffer
	for _, ch := range cfg.Channels {
		if !ch.Enabled || ch.Type != "wireguard" {
			continue
		}
		text, err := channels.RenderWireGuard(ch)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "# --- %s (%s) ---\n%s\n", ch.Name, channels.InterfaceName(ch), text)
	}
	if b.Len() == 0 {
		b.WriteString("# Нет активных каналов WireGuard.\n")
	}
	return b.String(), nil
}

func xrayActive(cfg *config.Config) bool {
	for _, ch := range cfg.Channels {
		if ch.Enabled && ch.Type == "xray" {
			return true
		}
	}
	return false
}

func renderXray(cfg *config.Config) (string, error) {
	var b bytes.Buffer
	for _, ch := range cfg.Channels {
		if !ch.Enabled || ch.Type != "xray" {
			continue
		}
		text, err := channels.RenderXray(ch)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "# --- %s (%s) ---\n%s\n", ch.Name, channels.InterfaceName(ch), text)
	}
	if b.Len() == 0 {
		b.WriteString("# Нет активных каналов Xray.\n")
	}
	return b.String(), nil
}

func xrayServersActive(cfg *config.Config) bool {
	for _, server := range cfg.VPNServers {
		if server.Enabled && server.Type == "xray" {
			return true
		}
	}
	return false
}

func renderXrayServers(cfg *config.Config) (string, error) {
	var b bytes.Buffer
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type != "xray" {
			continue
		}
		text, err := vpnservers.RenderXray(server, cfg)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "# --- %s (TCP %d) ---\n%s\n", server.Name, server.Port, text)
	}
	if b.Len() == 0 {
		b.WriteString("# Нет активных входящих серверов Xray.\n")
	}
	return b.String(), nil
}

func wifiActive(cfg *config.Config) bool {
	for _, radio := range cfg.WiFi {
		if radio.Enabled {
			return true
		}
	}
	return false
}

func renderWiFi(cfg *config.Config) (string, error) {
	var b bytes.Buffer
	for _, radio := range cfg.WiFi {
		if !radio.Enabled {
			continue
		}
		text, err := wifi.RenderRadio(radio, cfg)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "# --- %s ---\n%s\n", radio.Device, text)
	}
	if b.Len() == 0 {
		b.WriteString("# Нет активных точек доступа Wi-Fi.\n")
	}
	return b.String(), nil
}

func ocservActive(cfg *config.Config) bool {
	for _, server := range cfg.VPNServers {
		if server.Enabled && server.Type == "ocserv" {
			return true
		}
	}
	return false
}

func renderOcserv(cfg *config.Config) (string, error) {
	var b bytes.Buffer
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type != "ocserv" {
			continue
		}
		text, err := vpnservers.RenderOcserv(server, cfg, "/var/lib/netos/generated")
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "# --- %s (TCP/UDP %d) ---\n%s\n", server.Name, server.Port, text)
	}
	if b.Len() == 0 {
		b.WriteString("# Нет активных серверов OpenConnect.\n")
	}
	return b.String(), nil
}

// artifacts перечислены в том порядке, в каком их показывает панель: сперва
// то, что определяет доступность машины, затем службы, затем система.
var artifacts = []Artifact{
	{
		ID: "iptables", Title: "Правила iptables", Active: always,
		Render: func(cfg *config.Config) (string, error) {
			rs, err := firewall.Build(cfg)
			if err != nil {
				return "", err
			}
			out := rs.IPv4
			if rs.IPv6 != "" {
				out += "\n# --- ip6tables ---\n" + rs.IPv6
			}
			return out, nil
		},
	},
	{
		ID: "wireguard", Title: "Конфигурация WireGuard",
		Active: wireGuardActive, Render: renderWireGuard,
	},
	{
		ID: "xray", Title: "Конфигурация Xray",
		Active: xrayActive, Render: renderXray,
	},
	{
		ID: "xray-servers", Title: "Входящие серверы Xray",
		Active: xrayServersActive, Render: renderXrayServers,
	},
	{
		ID: "hostapd", Title: "Конфигурация Wi-Fi",
		Active: wifiActive, Render: renderWiFi,
	},
	{
		ID: "ocserv", Title: "Сервер OpenConnect",
		Active: ocservActive, Render: renderOcserv,
	},
	{
		ID: "dnsmasq", Title: "Конфигурация dnsmasq",
		Active: dnsmasq.Needed,
		Render: func(cfg *config.Config) (string, error) { return dnsmasq.Render(cfg), nil },
	},
	{
		ID: "isc-dhcp", Title: "Конфигурация ISC DHCP",
		Active: isc.Needed,
		Render: func(cfg *config.Config) (string, error) { return isc.Render(cfg), nil },
	},
	{
		ID: "kea-dhcp4", Title: "Конфигурация Kea DHCP",
		Active: kea.Needed,
		Render: func(cfg *config.Config) (string, error) { return kea.Render(cfg), nil },
	},
	{
		ID: "unbound", Title: "Конфигурация unbound",
		Active: unbound.Needed,
		Render: func(cfg *config.Config) (string, error) { return unbound.Render(cfg), nil },
	},
	{
		ID: "dnsproxy", Title: "Конфигурация dnsproxy",
		Active: dnsproxy.Needed,
		Render: func(cfg *config.Config) (string, error) { return dnsproxy.Render(cfg), nil },
	},
	{
		ID: "resolv", Title: "Резолвер роутера",
		Active: resolv.Needed,
		Render: func(cfg *config.Config) (string, error) { return resolv.Render(cfg), nil },
	},
	{
		ID: "network", Title: "Конфигурация сети", Active: always,
		// Персистентная конфигурация сети зависит от выбранного механизма;
		// печатаем то, что реально будет записано.
		Render: netconf.RenderFor,
	},
	{
		ID: "sysctl", Title: "Параметры ядра", Active: always,
		Render: func(cfg *config.Config) (string, error) { return sysctl.Render(cfg), nil },
	},
	{
		ID: "config", Title: "Конфигурация netOS", Active: always,
		Render: func(cfg *config.Config) (string, error) {
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetIndent("", "  ")
			if err := enc.Encode(cfg); err != nil {
				return "", err
			}
			return b.String(), nil
		},
	},
}

// All возвращает каталог целиком — в том числе артефакты, не участвующие в
// текущей конфигурации: `netos render unbound` обязан отвечать и тогда, когда
// unbound ещё не выбран, иначе им нельзя было бы воспользоваться при настройке.
func All() []Artifact { return artifacts }

// Active возвращает только то, что при такой конфигурации действительно
// работает на машине.
func Active(cfg *config.Config) []Artifact {
	var out []Artifact
	for _, a := range artifacts {
		if a.Active(cfg) {
			out = append(out, a)
		}
	}
	return out
}

// IDs перечисляет имена артефактов — для справки и дополнения команд.
func IDs() []string {
	out := make([]string, 0, len(artifacts))
	for _, a := range artifacts {
		out = append(out, a.ID)
	}
	return out
}

// ByID находит артефакт по имени.
func ByID(id string) (Artifact, bool) {
	for _, a := range artifacts {
		if a.ID == id {
			return a, true
		}
	}
	return Artifact{}, false
}

// Render собирает артефакт по имени.
func Render(id string, cfg *config.Config) (string, error) {
	a, ok := ByID(id)
	if !ok {
		return "", fmt.Errorf("неизвестный артефакт %q", id)
	}
	return a.Render(cfg)
}

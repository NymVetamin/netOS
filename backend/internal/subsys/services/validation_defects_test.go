package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Резолвер обязан слушать сегменты независимо от того, кто раздаёт адреса.
// С bind-dynamic dnsmasq принимает запросы только на перечисленных
// интерфейсах, а список приносила DHCP-часть конфига — и связка «DHCP не
// dnsmasq, резолвер dnsmasq» оставляла клиентов без DNS вовсе.
func TestDnsmasqListensOnSegmentsWithForeignDHCPProvider(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan-if", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan-if", RouterAddress: "192.168.50.1/24", Enabled: true}}
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.ForceLocal = true, "dnsmasq", false
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "isc-dhcp-server"

	rendered := NewDnsmasq(nil).Render(cfg)
	if !strings.Contains(rendered, "interface=br0") {
		t.Fatalf("резолвер не слушает сегмент:\n%s", rendered)
	}
}

// Клиент VPN получает в профиле адрес роутера как DNS-сервер. Пока интерфейсы
// серверов VPN не попадали в список, ответить ему было некому: запрос доходил
// через firewall, но сокета на этом интерфейсе не существовало.
func TestDnsmasqListensOnVPNServerInterfaces(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Enabled, cfg.DNS.Provider = true, "dnsmasq"
	cfg.VPNServers = []config.VPNServer{{ID: "s1", Type: "wireguard", Index: 1, Enabled: true}}

	rendered := NewDnsmasq(nil).Render(cfg)
	if !strings.Contains(rendered, "interface=wg-srv1") {
		t.Fatalf("резолвер не слушает интерфейс сервера VPN:\n%s", rendered)
	}
}

// Интерфейс не должен объявляться дважды: interface= в dnsmasq один на весь
// процесс, а не на роль.
func TestDnsmasqDoesNotRepeatInterfaces(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan-if", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{
		ID: "lan", Interface: "lan-if", RouterAddress: "192.168.50.1/24", Enabled: true,
		DHCPPool: config.DHCPPool{Enabled: true, Start: "192.168.50.100", End: "192.168.50.200", LeaseTime: 3600},
	}}
	cfg.DNS.Enabled, cfg.DNS.Provider = true, "dnsmasq"
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "dnsmasq"

	if got := strings.Count(NewDnsmasq(nil).Render(cfg), "interface=br0\n"); got != 1 {
		t.Fatalf("интерфейс объявлен %d раз вместо одного", got)
	}
}

// Unbound отвечает на зарезервированные и приватные зоны сам, встроенной
// local-zone, и она сильнее forward-zone: без явного transparent локальный
// домен .test и обратные зоны сегментов не разрешались вовсе.
func TestUnboundOpensLocalZonesForDnsmasqForwarding(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan-if", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan-if", RouterAddress: "192.168.50.1/24", Enabled: true}}
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.LocalDomain = true, "unbound", "r934.test"
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "dnsmasq"

	rendered := NewUnbound(nil).Render(cfg)
	for _, want := range []string{
		`local-zone: "r934.test." transparent`,
		`local-zone: "50.168.192.in-addr.arpa." transparent`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("нет %q:\n%s", want, rendered)
		}
	}
}

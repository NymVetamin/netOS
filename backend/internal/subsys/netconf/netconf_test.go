package netconf

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// routerConfig — роутер с бриджем из двух портов, VLAN поверх него, отдельным
// аплинком и подавленным IPv6.
func routerConfig() *config.Config {
	cfg := config.Default()
	cfg.System.NetworkBackend = "ifupdown"
	cfg.Interfaces = []config.Interface{
		{ID: "if-wan", Name: "eth0", Type: "physical"},
		{ID: "if-p1", Name: "eth1", Type: "physical"},
		{ID: "if-p2", Name: "eth2", Type: "physical"},
		{ID: "if-lan", Name: "br-lan", Type: "bridge", Members: []string{"eth1", "eth2"}},
		{ID: "if-guest", Name: "vl-guest", Type: "vlan", Parent: "br-lan", VLANID: 20},
	}
	cfg.Networks = []config.Network{
		{ID: "lan", Name: "LAN", Interface: "if-lan", RouterAddress: "192.168.10.1/24", Enabled: true},
		{ID: "guest", Name: "Гости", Interface: "if-guest", RouterAddress: "192.168.20.1/24", Enabled: true},
	}
	cfg.WANs = []config.WAN{
		{ID: "wan1", Name: "Провайдер", Interface: "if-wan", Enabled: true, Proto: "dhcp", Metric: 100},
	}
	return cfg
}

func TestIfupdownDescribesSegmentsAndLeavesUplinkToNetOS(t *testing.T) {
	out := renderIfupdown(routerConfig())

	// Сегменты обязаны существовать с загрузки.
	for _, want := range []string{
		"auto br-lan",
		"iface br-lan inet static",
		"address 192.168.10.1/24",
		"bridge_ports eth1 eth2",
		"auto vl-guest",
		"address 192.168.20.1/24",
		"vlan-raw-device br-lan",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет строки %q:\n%s", want, out)
		}
	}

	// Аплинк только поднимается: адрес по DHCP берёт клиент netOS, и второй
	// клиент на том же интерфейсе сломал бы метрики и Multi-WAN.
	if !strings.Contains(out, "auto eth0") || !strings.Contains(out, "iface eth0 inet manual") {
		t.Fatalf("аплинк описан неверно:\n%s", out)
	}
	if strings.Contains(out, "iface eth0 inet dhcp") {
		t.Fatalf("в файл попал второй клиент DHCP на аплинке:\n%s", out)
	}
	if strings.Contains(out, "gateway ") {
		t.Fatalf("в файл попал маршрут по умолчанию, которым владеет netOS:\n%s", out)
	}
}

func TestIfupdownMembersAreRaisedByTheirBridge(t *testing.T) {
	out := renderIfupdown(routerConfig())
	// auto на порту бриджа дало бы гонку: его поднимали бы и ifupdown, и сам
	// бридж через bridge_ports.
	for _, member := range []string{"eth1", "eth2"} {
		if strings.Contains(out, "auto "+member+"\n") {
			t.Fatalf("порт бриджа %s поднимается отдельно:\n%s", member, out)
		}
		if !strings.Contains(out, "iface "+member+" inet manual") {
			t.Fatalf("порт бриджа %s не описан:\n%s", member, out)
		}
	}
}

func TestIfupdownIsStableAcrossReordering(t *testing.T) {
	first := renderIfupdown(routerConfig())

	cfg := routerConfig()
	cfg.Interfaces[0], cfg.Interfaces[3] = cfg.Interfaces[3], cfg.Interfaces[0]
	second := renderIfupdown(cfg)

	// Иначе перестановка в конфигурации переписывала бы файл на ровном месте
	// и дёргала службу сети.
	if first != second {
		t.Fatalf("файл зависит от порядка элементов в конфигурации:\n%s\n---\n%s", first, second)
	}
}

func TestNetworkdBuildsDevicesAndNetworks(t *testing.T) {
	cfg := routerConfig()
	cfg.System.NetworkBackend = "networkd"
	files := renderNetworkd(cfg)

	bridge, ok := files["05-netos-br-lan.netdev"]
	if !ok {
		t.Fatalf("нет устройства бриджа, файлы: %v", keys(files))
	}
	if !strings.Contains(bridge, "Kind=bridge") || !strings.Contains(bridge, "STP=yes") {
		t.Fatalf("бридж описан неверно:\n%s", bridge)
	}

	vlan, ok := files["05-netos-vl-guest.netdev"]
	if !ok {
		t.Fatalf("нет устройства VLAN, файлы: %v", keys(files))
	}
	if !strings.Contains(vlan, "Kind=vlan") || !strings.Contains(vlan, "Id=20") {
		t.Fatalf("VLAN описан неверно:\n%s", vlan)
	}

	lan := files["05-netos-br-lan.network"]
	if !strings.Contains(lan, "Address=192.168.10.1/24") {
		t.Fatalf("адрес сегмента не назначен:\n%s", lan)
	}
	// Родитель обязан объявить дочерний VLAN, иначе networkd его не создаст.
	if !strings.Contains(lan, "VLAN=vl-guest") {
		t.Fatalf("родитель не объявил VLAN:\n%s", lan)
	}

	member := files["05-netos-eth1.network"]
	if !strings.Contains(member, "Bridge=br-lan") {
		t.Fatalf("порт не подчинён бриджу:\n%s", member)
	}

	wan := files["05-netos-eth0.network"]
	if !strings.Contains(wan, "DHCP=no") {
		t.Fatalf("networkd поднимет свой клиент DHCP на аплинке:\n%s", wan)
	}
	if strings.Contains(wan, "Address=") {
		t.Fatalf("аплинку назначен адрес в обход netOS:\n%s", wan)
	}
	// Линк должен быть поднят и без адреса: по нему пойдёт разговор клиента
	// DHCP или PPPoE.
	if !strings.Contains(wan, "ActivationPolicy=up") {
		t.Fatalf("линк аплинка не поднимается:\n%s", wan)
	}
}

func TestNetworkdSuppressesIPv6(t *testing.T) {
	cfg := routerConfig()
	cfg.System.NetworkBackend = "networkd"
	cfg.IPv6.Mode = "off"
	lan := renderNetworkd(cfg)["05-netos-br-lan.network"]
	for _, want := range []string{"LinkLocalAddressing=no", "IPv6AcceptRA=no"} {
		if !strings.Contains(lan, want) {
			t.Fatalf("нет %q — IPv6 вернётся через автонастройку:\n%s", want, lan)
		}
	}

	cfg.IPv6.Mode = "passthrough"
	lan = renderNetworkd(cfg)["05-netos-br-lan.network"]
	if strings.Contains(lan, "LinkLocalAddressing=no") {
		t.Fatalf("режим passthrough всё равно выключает IPv6:\n%s", lan)
	}
}

func TestBackendNetosGeneratesNothing(t *testing.T) {
	cfg := routerConfig()
	cfg.System.NetworkBackend = "netos"
	if render(cfg) != "" {
		t.Fatal("при прямом управлении в систему что-то пишется")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// networkd берёт первый .network, чей Match подошёл, перебирая файлы в
// лексическом порядке. Имя, сортирующееся после штатных 10-* и 20-*, означало
// бы, что конфигурация netOS молча не работает.
func TestNetworkdFilesSortBeforeDistributionDefaults(t *testing.T) {
	cfg := routerConfig()
	cfg.System.NetworkBackend = "networkd"
	for name := range renderNetworkd(cfg) {
		for _, other := range []string{"10-all.network", "10-netplan-eth0.network", "20-wired.network", "80-container.network"} {
			if name >= other {
				t.Fatalf("файл %q разбирается позже штатного %q и не сработает", name, other)
			}
		}
	}
}

// networkd снимает адреса и маршруты, которых нет в его файлах. Наши файлы
// описывают только то, что должно существовать с загрузки, поэтому без
// KeepConfiguration он стёр бы адрес аплинка и маршруты с метриками.
func TestNetworkdKeepsConfigurationMadeByNetOS(t *testing.T) {
	cfg := routerConfig()
	cfg.System.NetworkBackend = "networkd"
	for name, content := range renderNetworkd(cfg) {
		if !strings.HasSuffix(name, ".network") {
			continue
		}
		if !strings.Contains(content, "KeepConfiguration=yes") {
			t.Fatalf("%s разрешает networkd снять работу netOS:\n%s", name, content)
		}
	}
}

// Переключение механизма не должно оставлять на машине два описания одной
// сети: какое из них отработает при загрузке, зависело бы от порядка служб.
func TestSwitchingBackendLeavesNoStaleDescription(t *testing.T) {
	cfg := routerConfig()
	cfg.System.NetworkBackend = "netos"
	if got := render(cfg); got != "" {
		t.Fatalf("прямое управление всё равно что-то генерирует:\n%s", got)
	}
	cfg.System.NetworkBackend = "ifupdown"
	if !strings.Contains(render(cfg), "iface br-lan inet static") {
		t.Fatal("ifupdown ничего не сгенерировал")
	}
	cfg.System.NetworkBackend = "networkd"
	if !strings.Contains(render(cfg), "Kind=bridge") {
		t.Fatal("networkd ничего не сгенерировал")
	}
}

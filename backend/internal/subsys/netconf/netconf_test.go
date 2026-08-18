package netconf

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
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

// Выбор «netOS напрямую» обязан что-то значить. На машине, где сетью уже
// управляет systemd-networkd, он продолжит выдавать адрес по DHCP, netOS будет
// считать тот же адрес своим статическим, и до истечения аренды никто не
// заметит, что панель говорит одно, а машиной правит другое.
func TestBackendNetosTakesInterfacesAwayFromNetworkd(t *testing.T) {
	cfg := routerConfig()
	cfg.System.NetworkBackend = "netos"
	out := render(cfg)

	for _, name := range []string{"eth0", "eth1", "eth2", "br-lan", "vl-guest"} {
		if !strings.Contains(out, "Name="+name) {
			t.Fatalf("интерфейс %s не отобран у networkd:\n%s", name, out)
		}
	}
	if got := strings.Count(out, "Unmanaged=yes"); got != 5 {
		t.Fatalf("отобрано интерфейсов: %d, ожидалось 5:\n%s", got, out)
	}
	// Ничего, кроме отказа от управления, в этом режиме писаться не должно:
	// адреса назначает netOS.
	if strings.Contains(out, "Address=") || strings.Contains(out, "Bridge=") {
		t.Fatalf("в режиме прямого управления networkd получил настройки:\n%s", out)
	}
	// Чужие интерфейсы не наши: машина может обслуживать и другие сети.
	if strings.Contains(out, "Name=eth9") {
		t.Fatalf("отобран интерфейс, которого нет в конфигурации:\n%s", out)
	}
}

// Объявление интерфейса в чужом файле ifupdown надо замечать, но не путать с
// похожим именем: eth0 не должен находиться внутри eth0.100.
func TestIfupdownDeclarationIsMatchedExactly(t *testing.T) {
	vlan := "auto eth0.100\niface eth0.100 inet dhcp\n"
	if mentionsInterface(vlan, "eth0") {
		t.Fatal("eth0 нашёлся внутри eth0.100")
	}
	if !mentionsInterface(vlan, "eth0.100") {
		t.Fatal("объявление eth0.100 не найдено")
	}
	if !mentionsInterface("allow-hotplug eth1\n", "eth1") {
		t.Fatal("allow-hotplug не распознан как объявление")
	}
	// Упоминание в комментарии объявлением не является.
	if mentionsInterface("# тут был eth2\n", "eth2") {
		t.Fatal("комментарий принят за объявление")
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

// У каждого режима свой результат, и он не пустой ни в одном из них: даже
// прямое управление требует сказать systemd-networkd не трогать интерфейсы.
func TestEachBackendProducesItsOwnDescription(t *testing.T) {
	cfg := routerConfig()

	cfg.System.NetworkBackend = "netos"
	direct := render(cfg)
	if !strings.Contains(direct, "Unmanaged=yes") {
		t.Fatalf("прямое управление не отбирает интерфейсы:\n%s", direct)
	}

	cfg.System.NetworkBackend = "ifupdown"
	ifupdown := render(cfg)
	if !strings.Contains(ifupdown, "iface br-lan inet static") {
		t.Fatal("ifupdown ничего не сгенерировал")
	}

	cfg.System.NetworkBackend = "networkd"
	networkd := render(cfg)
	if !strings.Contains(networkd, "Kind=bridge") {
		t.Fatal("networkd ничего не сгенерировал")
	}

	// Описания обязаны различаться: одинаковый результат означал бы, что
	// выбор в панели ни на что не влияет.
	if direct == ifupdown || direct == networkd || ifupdown == networkd {
		t.Fatal("режимы дают одинаковый результат — выбор в панели ничего не значит")
	}
	// И режим прямого управления не должен настраивать сеть чужими руками.
	if strings.Contains(direct, "Address=") || strings.Contains(direct, "Kind=") {
		t.Fatalf("прямое управление настраивает сеть через networkd:\n%s", direct)
	}
}

// Порядок применения — часть механизма передачи управления, а не деталь.
// systemd-networkd снимает выданные им адреса, когда интерфейс становится
// неуправляемым, поэтому netconf обязан отработать до подсистем, которые
// назначают адреса: разрыв закрывается тем, что они идут сразу следом.
func TestNetconfRunsBeforeAddressingSubsystems(t *testing.T) {
	position := map[string]int{}
	for i, name := range apply.Order {
		position[name] = i
	}
	netconf, ok := position["netconf"]
	if !ok {
		t.Fatal("подсистема netconf отсутствует в порядке применения")
	}
	for _, later := range []string{"interfaces", "networks", "wan"} {
		if position[later] < netconf {
			t.Fatalf("%s применяется раньше netconf: адрес, снятый networkd, некому вернуть", later)
		}
	}
}

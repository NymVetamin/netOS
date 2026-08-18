package netconf

import (
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// renderIfupdown собирает /etc/network/interfaces.d/netos.conf.
//
// Файл кладётся в interfaces.d, а не в сам /etc/network/interfaces: штатный
// файл дистрибутива netOS не трогает, и его удаление возвращает машину в
// исходное состояние.
func renderIfupdown(cfg *config.Config) string {
	p := buildPlan(cfg)

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("#")
	w("# Здесь описано только то, что статично: бриджи, VLAN, агрегаты и адреса")
	w("# сегментов. Аплинки подняты, но не настроены — их адресами, маршрутами и")
	w("# метриками управляет netOS.")

	for _, iface := range p.Order {
		w("")
		renderIfupdownStanza(&b, p, iface)
	}
	return b.String()
}

func renderIfupdownStanza(b *strings.Builder, p plan, iface config.Interface) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }

	address, hasAddress := p.Address[iface.Name]
	// Подчинённый порт поднимает не auto, а сам агрегат: allow-hotplug дал бы
	// гонку между ними.
	master, isMember := p.Master[iface.Name]

	if isMember {
		w("# порт агрегата %s", master.Name)
		w("iface %s inet manual", iface.Name)
	} else {
		w("auto %s", iface.Name)
		if hasAddress {
			w("iface %s inet static", iface.Name)
			w("    address %s", address)
		} else {
			if p.managedByNetOS(iface) {
				w("# аплинк: адрес и маршрут назначает netOS")
			}
			w("iface %s inet manual", iface.Name)
		}
	}

	switch iface.Type {
	case "bridge":
		members := iface.Members
		if len(members) == 0 {
			// Бридж без портов всё равно должен подняться: в него могут
			// добавляться интерфейсы каналов и точки доступа.
			w("    bridge_ports none")
		} else {
			w("    bridge_ports %s", strings.Join(members, " "))
		}
		w("    bridge_stp on")
		// Без задержки бридж не пропускает трафик первые секунды после
		// поднятия, и клиент успевает не получить адрес по DHCP.
		w("    bridge_fd 0")
	case "vlan":
		w("    vlan-raw-device %s", iface.Parent)
	case "bond":
		if len(iface.Members) > 0 {
			w("    bond-slaves %s", strings.Join(iface.Members, " "))
		}
		w("    bond-mode 802.3ad")
	}

	if iface.MTU > 0 {
		w("    mtu %d", iface.MTU)
	}
	if iface.MAC != "" {
		w("    hwaddress ether %s", iface.MAC)
	}
}

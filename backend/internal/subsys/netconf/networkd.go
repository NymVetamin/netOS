package netconf

import (
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// renderNetworkd собирает файлы для systemd-networkd: имя файла → содержимое.
//
// Числовые префиксы задают порядок разбора: устройства должны быть объявлены
// раньше, чем на них ссылаются сети.
func renderNetworkd(cfg *config.Config) map[string]string {
	p := buildPlan(cfg)
	files := map[string]string{}

	for _, iface := range p.Order {
		if netdev := renderNetdev(iface); netdev != "" {
			files[fmt.Sprintf("%s%s.netdev", networkdPrefix, iface.Name)] = netdev
		}
		files[fmt.Sprintf("%s%s.network", networkdPrefix, iface.Name)] = renderNetwork(p, iface)
	}
	return files
}

// renderNetdev описывает виртуальное устройство. Физические порты существуют
// сами по себе, для них файл не нужен.
func renderNetdev(iface config.Interface) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	kind := ""
	switch iface.Type {
	case "bridge":
		kind = "bridge"
	case "bond":
		kind = "bond"
	case "vlan":
		kind = "vlan"
	default:
		return ""
	}

	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("[NetDev]")
	w("Name=%s", iface.Name)
	w("Kind=%s", kind)
	if iface.MTU > 0 {
		w("MTUBytes=%d", iface.MTU)
	}
	if iface.MAC != "" {
		w("MACAddress=%s", iface.MAC)
	}

	switch iface.Type {
	case "bridge":
		w("")
		w("[Bridge]")
		w("STP=yes")
		// Zero is invalid with STP enabled; use the kernel's minimum so
		// networkd can apply the bridge parameters during creation as well.
		w("ForwardDelaySec=2s")
	case "bond":
		w("")
		w("[Bond]")
		w("Mode=%s", config.BondMode)
	case "vlan":
		w("")
		w("[VLAN]")
		w("Id=%d", iface.VLANID)
	}
	return b.String()
}

func renderNetwork(p plan, iface config.Interface) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("[Match]")
	w("Name=%s", iface.Name)
	w("")
	w("[Network]")

	// Свой клиент DHCP на аплинке уже есть, и второй сломал бы метрики и
	// переключение между каналами.
	w("DHCP=no")
	// Без этого networkd считает своими все адреса и маршруты интерфейса и
	// снимает те, которых нет в файле, — то есть стёр бы работу netOS: адрес
	// аплинка, маршруты с метриками, адреса каналов. Мы описываем только то,
	// что должно существовать с загрузки, а не полный список.
	w("KeepConfiguration=yes")

	if address, ok := p.Address[iface.Name]; ok {
		w("Address=%s", address)
	}
	if master, ok := p.Master[iface.Name]; ok {
		switch master.Type {
		case "bridge":
			w("Bridge=%s", master.Name)
		case "bond":
			w("Bond=%s", master.Name)
		}
	}
	for _, vlan := range p.VLANs[iface.Name] {
		w("VLAN=%s", vlan.Name)
	}

	if p.SuppressIPv6 {
		// IPv6 подавляется на всех уровнях; networkd не должен возвращать его
		// обратно ни автонастройкой, ни link-local адресом.
		w("LinkLocalAddressing=no")
		w("IPv6AcceptRA=no")
	} else {
		w("IPv6AcceptRA=no")
	}

	w("")
	w("[Link]")
	// Линк держим поднятым даже без адреса: на аплинке по нему пойдёт разговор
	// клиента DHCP или PPPoE, а на пустом бридже — трафик каналов.
	w("ActivationPolicy=up")
	if !iface.Enabled {
		w("RequiredForOnline=no")
	} else if _, addressed := p.Address[iface.Name]; addressed {
		w("RequiredForOnline=routable")
	} else {
		// WAN addresses belong to netOS, which may start after cloud-init
		// waits for network-online. Requiring an address creates a boot cycle.
		w("RequiredForOnline=carrier")
	}
	if iface.MTU > 0 && iface.Type == "physical" {
		w("MTUBytes=%d", iface.MTU)
	}
	return b.String()
}

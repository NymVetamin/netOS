// Package bootstrap строит стартовую конфигурацию по фактическому состоянию
// машины: какие есть интерфейсы, через какой из них идёт маршрут по умолчанию,
// какие подсети уже заняты.
//
// Цель — чтобы сразу после установки роутер работал, а не требовал заполнить
// десяток форм. Пользователь получает готовую конфигурацию и правит её.
package bootstrap

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Detected — то, что удалось выяснить о машине.
type Detected struct {
	// WANInterface — интерфейс, через который сейчас идёт маршрут по умолчанию.
	WANInterface string
	// WANAddress и WANGateway заполняются, если адрес назначен статически или
	// уже получен по DHCP.
	WANAddress string
	WANGateway string
	// LANCandidates — интерфейсы без адреса, годящиеся под локальную сеть.
	LANCandidates []string
	// AllInterfaces — все физические интерфейсы, кроме петли.
	AllInterfaces []string
	// ManagementCIDR — подсеть, из которой сейчас подключён администратор.
	// Используется, чтобы не отрезать себе доступ правилами файрволла.
	ManagementCIDR string
	// OccupiedCIDRs contains every IPv4 subnet already present on a physical
	// interface. LAN bootstrap must avoid all of them, not only the uplink.
	OccupiedCIDRs []string
}

// Detect опрашивает систему.
func Detect(ctx context.Context, r system.Runner) (*Detected, error) {
	d := &Detected{}

	names, err := physicalInterfaces()
	if err != nil {
		return nil, err
	}
	d.AllInterfaces = names

	// Интерфейс маршрута по умолчанию — почти наверняка аплинк.
	out, err := r.Run(ctx, "ip", "-o", "route", "show", "default")
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			var iface, gateway string
			for i, f := range fields {
				if f == "dev" && i+1 < len(fields) {
					iface = fields[i+1]
				}
				if f == "via" && i+1 < len(fields) {
					gateway = fields[i+1]
				}
			}
			if iface != "" {
				d.WANInterface, d.WANGateway = iface, gateway
				break
			}
		}
	}

	for _, name := range names {
		addrs, err := addressesOf(ctx, r, name)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			d.OccupiedCIDRs = append(d.OccupiedCIDRs, subnetOf(addr))
		}
		if name == d.WANInterface && len(addrs) > 0 {
			d.WANAddress = addrs[0]
			continue
		}
		// A Wi-Fi radio is exposed as a physical netdev too, but a station-mode
		// mac80211 interface cannot be enslaved directly to a Linux bridge.
		// Wi-Fi is configured separately and hostapd creates/attaches the AP;
		// choosing a fresh or hwsim radio as factory LAN makes every daemon start
		// fail while repeatedly disturbing the management uplink.
		if len(addrs) == 0 && !isWirelessInterface(name) {
			d.LANCandidates = append(d.LANCandidates, name)
		}
	}

	if d.WANAddress != "" {
		d.ManagementCIDR = subnetOf(d.WANAddress)
	}
	return d, nil
}

// BuildInitial собирает стартовую конфигурацию.
//
// Если в машине один интерфейс — а так бывает на VPS — LAN-сегмент создаётся
// на dummy-интерфейсе. Роутер в таком виде полноценно работает как VPN-шлюз
// для входящих подключений, а физический LAN добавляется, когда появится
// вторая карта.
func BuildInitial(d *Detected) *config.Config {
	cfg := config.Default()

	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		cfg.System.Hostname = hostname
	}

	// --- аплинк ---
	if d.WANInterface != "" {
		cfg.Interfaces = append(cfg.Interfaces, config.Interface{
			ID:      "if-wan",
			Name:    d.WANInterface,
			Type:    "physical",
			Enabled: true,
		})
		wan := config.WAN{
			ID:        "wan",
			Index:     1,
			Name:      "Аплинк",
			Interface: "if-wan",
			Enabled:   true,
			Proto:     "dhcp",
			Metric:    100,
			Weight:    1,
			Probe:     config.DefaultProbe(),
		}
		// Если адрес и шлюз уже известны, фиксируем их статикой: перевод
		// работающего аплинка на DHCP-клиента netOS в момент установки — самый
		// быстрый способ потерять связь с машиной.
		if d.WANAddress != "" && d.WANGateway != "" {
			wan.Proto = "static"
			wan.Address = d.WANAddress
			wan.Gateway = d.WANGateway
		}
		cfg.WANs = append(cfg.WANs, wan)

		// Маскарад привязываем к конкретному интерфейсу, а не к зоне: в ядре
		// правило всё равно живёт на интерфейсе, и лишний слой абстракции
		// только мешает понять, что произойдёт.
		cfg.Firewall.NAT = append(cfg.Firewall.NAT, config.NATRule{
			ID:        "nat-wan",
			Name:      "Подменять адреса клиентов на адрес роутера",
			Enabled:   true,
			System:    true,
			Direction: "source",
			Interface: d.WANInterface,
			Comment: "Без этого клиенты локальной сети не выйдут в интернет: " +
				"их адреса там не маршрутизируются.",
		})
	}

	// --- локальная сеть ---
	//
	// Сегмент создаётся только если есть свободная сетевая карта. На машине с
	// одной картой — а это обычный VPS — локальной сети физически нет, и
	// поднимать ради неё виртуальный интерфейс незачем: роутер после установки
	// доступен по тому адресу, который у него уже есть.
	if len(d.LANCandidates) == 0 {
		cfg.Normalize()
		return cfg
	}

	lanIface := ""
	{
		lanIface = d.LANCandidates[0]
		cfg.Interfaces = append(cfg.Interfaces, config.Interface{
			ID:      "if-lan",
			Name:    lanIface,
			Type:    "physical",
			Enabled: true,
		})
		cfg.Interfaces = append(cfg.Interfaces, config.Interface{
			ID:      "br-lan",
			Name:    "br-lan",
			Type:    "bridge",
			Members: []string{lanIface},
			Enabled: true,
		})
	}

	subnet := pickFreeSubnet(d)
	pool := config.DefaultDHCPPool(subnet.poolStart, subnet.poolEnd)
	// Пул подготовлен, но выключен: раздавать адреса роутер начнёт только
	// после того, как администратор установит компонент DHCP и включит его.
	pool.Enabled = false

	cfg.Networks = append(cfg.Networks, config.Network{
		ID:            "lan",
		Name:          "Локальная сеть",
		Interface:     "br-lan",
		RouterAddress: subnet.routerAddr,
		Enabled:       true,
		Zone:          "lan",
		DHCPPool:      pool,
	})

	cfg.Normalize()
	return cfg
}

type subnetChoice struct {
	routerAddr string
	poolStart  string
	poolEnd    string
}

// pickFreeSubnet выбирает подсеть для LAN, избегая той, в которой находится
// сам администратор: совпадение сетей означало бы мгновенную потерю доступа.
func pickFreeSubnet(d *Detected) subnetChoice {
	candidates := []struct{ third int }{{10}, {20}, {30}, {40}, {50}}
	occupied := make(map[string]bool, len(d.OccupiedCIDRs)+1)
	for _, cidr := range d.OccupiedCIDRs {
		occupied[cidr] = true
	}
	if d.ManagementCIDR != "" {
		occupied[d.ManagementCIDR] = true
	}

	for _, c := range candidates {
		base := fmt.Sprintf("192.168.%d.", c.third)
		if occupied[base+"0/24"] {
			continue
		}
		return subnetChoice{
			routerAddr: base + "1/24",
			poolStart:  base + "100",
			poolEnd:    base + "200",
		}
	}
	return subnetChoice{
		routerAddr: "10.77.0.1/24",
		poolStart:  "10.77.0.100",
		poolEnd:    "10.77.0.200",
	}
}

// ---------------------------------------------------------------------------

// physicalInterfaces перечисляет сетевые карты, отсеивая петлю и виртуальные
// интерфейсы, созданные не нами.
func physicalInterfaces() ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		// У физических карт в sysfs есть ссылка на устройство шины.
		if _, err := os.Stat(filepath.Join(sysClassNet, name, "device")); err != nil {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

var sysClassNet = "/sys/class/net"

func isWirelessInterface(name string) bool {
	_, err := os.Stat(filepath.Join(sysClassNet, name, "wireless"))
	return err == nil
}

func addressesOf(ctx context.Context, r system.Runner, iface string) ([]string, error) {
	out, err := r.Run(ctx, "ip", "-4", "-o", "addr", "show", "dev", iface)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				addrs = append(addrs, fields[i+1])
			}
		}
	}
	return addrs, nil
}

func subnetOf(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return cidr
	}
	return prefix.Masked().String()
}

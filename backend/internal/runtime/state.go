// Package runtime собирает фактическое состояние системы: кто подключён,
// какие адреса выданы, сколько прошло трафика.
//
// Это принципиально отличается от пакета config: там желаемое состояние,
// здесь — наблюдаемое. Панель показывает и то, и другое, и расхождения между
// ними обычно и есть то, что администратор ищет.
package runtime

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/system"
)

// Lease — выданная аренда DHCP.
type Lease struct {
	MAC      string    `json:"mac"`
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname"`
	Expires  time.Time `json:"expires"`
}

// ARPEntry — запись таблицы соседей.
type ARPEntry struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	State     string `json:"state"`
}

// InterfaceStat — счётчики интерфейса.
type InterfaceStat struct {
	Name      string `json:"name"`
	Up        bool   `json:"up"`
	MAC       string `json:"mac"`
	MTU       int    `json:"mtu"`
	RXBytes   int64  `json:"rx_bytes"`
	TXBytes   int64  `json:"tx_bytes"`
	RXPackets int64  `json:"rx_packets"`
	TXPackets int64  `json:"tx_packets"`
	RXErrors  int64  `json:"rx_errors"`
	TXErrors  int64  `json:"tx_errors"`
}

// Client — устройство в сети, каким его видит роутер прямо сейчас.
type Client struct {
	MAC       string     `json:"mac"`
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname"`
	Interface string     `json:"interface"`
	Online    bool       `json:"online"`
	Source    string     `json:"source"` // dhcp | arp | both
	Expires   *time.Time `json:"expires,omitempty"`
}

// Collector читает состояние системы.
type Collector struct {
	Runner    system.Runner
	LeasePath string
}

func NewCollector(r system.Runner, leasePath string) *Collector {
	return &Collector{Runner: r, LeasePath: leasePath}
}

// Leases читает файл аренд dnsmasq. Формат строки:
// <срок в unix> <mac> <ip> <имя> <client-id>
func (c *Collector) Leases() ([]Lease, error) {
	f, err := os.Open(c.LeasePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // сервер ещё никому не выдавал адрес
		}
		return nil, err
	}
	defer f.Close()

	var out []Lease
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ts, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		hostname := fields[3]
		if hostname == "*" {
			hostname = ""
		}
		out = append(out, Lease{
			MAC:      strings.ToLower(fields[1]),
			IP:       fields[2],
			Hostname: hostname,
			Expires:  time.Unix(ts, 0),
		})
	}
	return out, scanner.Err()
}

// ARP читает таблицу соседей через ip neigh.
func (c *Collector) ARP(ctx context.Context) ([]ARPEntry, error) {
	out, err := c.Runner.Run(ctx, "ip", "-4", "neigh", "show")
	if err != nil {
		return nil, err
	}

	var entries []ARPEntry
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		e := ARPEntry{IP: fields[0]}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "dev":
				if i+1 < len(fields) {
					e.Interface = fields[i+1]
				}
			case "lladdr":
				if i+1 < len(fields) {
					e.MAC = strings.ToLower(fields[i+1])
				}
			}
		}
		// Последнее поле — состояние: REACHABLE, STALE, FAILED и так далее.
		e.State = fields[len(fields)-1]
		if e.MAC == "" {
			continue // запись без адреса канального уровня бесполезна
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// InterfaceStats читает счётчики из sysfs — это дешевле разбора вывода ip -s.
func (c *Collector) InterfaceStats() ([]InterfaceStat, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}

	var out []InterfaceStat
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		base := "/sys/class/net/" + name
		stat := InterfaceStat{
			Name:      name,
			MAC:       readString(base + "/address"),
			MTU:       int(readInt(base + "/mtu")),
			Up:        readString(base+"/operstate") == "up",
			RXBytes:   readInt(base + "/statistics/rx_bytes"),
			TXBytes:   readInt(base + "/statistics/tx_bytes"),
			RXPackets: readInt(base + "/statistics/rx_packets"),
			TXPackets: readInt(base + "/statistics/tx_packets"),
			RXErrors:  readInt(base + "/statistics/rx_errors"),
			TXErrors:  readInt(base + "/statistics/tx_errors"),
		}
		out = append(out, stat)
	}
	return out, nil
}

// Clients сводит аренды и ARP в единый список устройств.
//
// Аренда без записи ARP означает, что устройство получало адрес, но сейчас
// молчит; запись ARP без аренды — что адрес прописан статически на самом
// устройстве. Оба случая администратору полезно видеть.
func (c *Collector) Clients(ctx context.Context) ([]Client, error) {
	leases, err := c.Leases()
	if err != nil {
		return nil, err
	}
	arp, err := c.ARP(ctx)
	if err != nil {
		return nil, err
	}

	byMAC := map[string]*Client{}

	for _, l := range leases {
		expires := l.Expires
		byMAC[l.MAC] = &Client{
			MAC:      l.MAC,
			IP:       l.IP,
			Hostname: l.Hostname,
			Source:   "dhcp",
			Expires:  &expires,
		}
	}

	for _, a := range arp {
		reachable := a.State == "REACHABLE" || a.State == "DELAY" || a.State == "STALE"
		if cl, ok := byMAC[a.MAC]; ok {
			cl.Interface = a.Interface
			cl.Online = reachable
			cl.Source = "both"
			if cl.IP == "" {
				cl.IP = a.IP
			}
			continue
		}
		byMAC[a.MAC] = &Client{
			MAC:       a.MAC,
			IP:        a.IP,
			Interface: a.Interface,
			Online:    reachable,
			Source:    "arp",
		}
	}

	out := make([]Client, 0, len(byMAC))
	for _, cl := range byMAC {
		out = append(out, *cl)
	}
	return out, nil
}

// Routes отдаёт таблицу маршрутизации в сыром виде — панель показывает её
// как есть, потому что администраторы читают её именно в этом формате.
func (c *Collector) Routes(ctx context.Context, table string) (string, error) {
	args := []string{"-4", "route", "show"}
	if table != "" {
		args = append(args, "table", table)
	}
	return c.Runner.Run(ctx, "ip", args...)
}

// Rules отдаёт правила выбора таблиц маршрутизации — основу движка каналов.
func (c *Collector) Rules(ctx context.Context) (string, error) {
	return c.Runner.Run(ctx, "ip", "-4", "rule", "show")
}

// ConntrackCount возвращает число отслеживаемых соединений.
func (c *Collector) ConntrackCount() int64 {
	return readInt("/proc/sys/net/netfilter/nf_conntrack_count")
}

func readString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readInt(path string) int64 {
	v, err := strconv.ParseInt(readString(path), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

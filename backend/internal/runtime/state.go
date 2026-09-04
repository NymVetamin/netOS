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
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
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
	Name string `json:"name"`
	// Physical distinguishes configurable hardware ports from bridges, VLANs,
	// tunnels and other runtime-only links. A hot-added NIC must be visible to
	// the configuration UI without adopting every transient virtual interface.
	Physical  bool   `json:"physical"`
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
	Runner        system.Runner
	LeasePath     string
	LeaseProvider func() string
	SysClassNet   string
	ProcNetfilter string
}

func NewCollector(r system.Runner, leasePath string) *Collector {
	return &Collector{
		Runner: r, LeasePath: leasePath, SysClassNet: "/sys/class/net",
		ProcNetfilter: "/proc/sys/net/netfilter",
	}
}

// Leases читает файл аренд dnsmasq. Формат строки:
// <срок в unix> <mac> <ip> <имя> <client-id>
func (c *Collector) Leases() ([]Lease, error) {
	provider := "dnsmasq"
	if c.LeaseProvider != nil {
		provider = c.LeaseProvider()
	}
	path := leasePathForProvider(provider, c.LeasePath)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // сервер ещё никому не выдавал адрес
		}
		return nil, err
	}
	defer f.Close()

	if provider == "isc-dhcp-server" {
		return parseISCLeases(f)
	}
	if provider == "kea" {
		return parseKeaLeases(f)
	}
	return parseDnsmasqLeases(f)
}

func leasePathForProvider(provider, dnsmasqPath string) string {
	switch provider {
	case "isc-dhcp-server":
		return "/var/lib/netos/dhcpd.leases"
	case "kea":
		// Keep this in sync with services.keaLeasePath. Debian's AppArmor
		// profile only permits Kea's writable database below /var/lib/kea.
		return "/var/lib/kea/netos-leases4.csv"
	default:
		return dnsmasqPath
	}
}

func parseDnsmasqLeases(f *os.File) ([]Lease, error) {
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

func parseISCLeases(f *os.File) ([]Lease, error) {
	latest := map[string]Lease{}
	var current Lease
	active := false
	inLease := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "lease ") && strings.HasSuffix(line, " {") {
			current = Lease{IP: strings.TrimSuffix(strings.TrimPrefix(line, "lease "), " {")}
			active, inLease = false, true
			continue
		}
		if !inLease {
			continue
		}
		switch {
		case strings.HasPrefix(line, "hardware ethernet "):
			current.MAC = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "hardware ethernet "), ";"))
		case strings.HasPrefix(line, "client-hostname "):
			current.Hostname = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, "client-hostname "), ";"), "\"")
		case strings.HasPrefix(line, "ends "):
			value := strings.TrimSuffix(strings.TrimPrefix(line, "ends "), ";")
			parts := strings.Fields(value)
			if len(parts) == 3 {
				if tm, err := time.ParseInLocation("2006/01/02 15:04:05", parts[1]+" "+parts[2], time.UTC); err == nil {
					current.Expires = tm
				}
			}
		case line == "binding state active;":
			active = true
		case line == "}":
			delete(latest, current.IP)
			if active && current.IP != "" && current.MAC != "" {
				latest[current.IP] = current
			}
			inLease = false
		}
	}
	var out []Lease
	for _, lease := range latest {
		out = append(out, lease)
	}
	return out, scanner.Err()
}

func parseKeaLeases(f *os.File) ([]Lease, error) {
	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	index := map[string]int{}
	for i, name := range rows[0] {
		index[name] = i
	}
	field := func(row []string, name string) string {
		i, ok := index[name]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}
	var out []Lease
	for _, row := range rows[1:] {
		ip, mac := field(row, "address"), strings.ToLower(field(row, "hwaddr"))
		if ip == "" || mac == "" {
			continue
		}
		if state := field(row, "state"); state != "" && state != "0" {
			continue
		}
		expires, _ := strconv.ParseInt(field(row, "expire"), 10, 64)
		out = append(out, Lease{IP: ip, MAC: mac, Hostname: field(row, "hostname"), Expires: time.Unix(expires, 0)})
	}
	return out, nil
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
	root := c.SysClassNet
	if root == "" {
		root = "/sys/class/net"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	var out []InterfaceStat
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		base := filepath.Join(root, name)
		stat := InterfaceStat{
			Name:      name,
			Physical:  pathExists(filepath.Join(base, "device")),
			MAC:       readString(base + "/address"),
			MTU:       int(readInt(base + "/mtu")),
			Up:        interfaceIsUp(readString(base+"/operstate"), readString(base+"/flags")),
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

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// interfaceIsUp учитывает TUN/TAP: ядро обычно сообщает им operstate=unknown,
// даже когда интерфейс административно поднят и передаёт трафик. Флаг IFF_UP
// в таком случае является точным признаком. Для обычного operstate=down флаг
// не переопределяем — физический порт без carrier должен остаться «down».
func interfaceIsUp(operstate, flags string) bool {
	if operstate == "up" {
		return true
	}
	if operstate != "unknown" {
		return false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(flags), 0, 64)
	return err == nil && value&1 != 0
}

// Clients сводит аренды и ARP в единый список устройств.
//
// Аренда без записи ARP означает, что устройство получало адрес, но сейчас
// молчит; запись ARP без аренды — что адрес прописан статически на самом
// устройстве. Оба случая администратору полезно видеть.
func (c *Collector) Clients(ctx context.Context, localInterfaces map[string]bool) ([]Client, error) {
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
		// ip neigh содержит и соседей на WAN. Шлюз провайдера — не клиент
		// локальной сети: показывать для него «заблокировать» или назначение
		// канала опасно, поскольку администратор может отрезать весь аплинк.
		if !localInterfaces[a.Interface] {
			continue
		}
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return out[i].MAC < out[j].MAC
	})
	return out, nil
}

// Route — разобранная запись таблицы маршрутизации.
type Route struct {
	Type        string `json:"type"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Source      string `json:"source"`
	Metric      int    `json:"metric"`
	// Origin — откуда маршрут взялся: kernel, dhcp, static, boot, ra.
	// Именно это отличает маршрут, полученный от провайдера, от прописанного
	// администратором вручную, и именно этого не видно в сыром выводе без
	// привычки его читать.
	Origin string `json:"origin"`
	Table  string `json:"table"`
	Raw    string `json:"raw"`
}

// Routes отдаёт таблицу маршрутизации в сыром виде.
func (c *Collector) Routes(ctx context.Context, table string) (string, error) {
	args := []string{"-4", "route", "show"}
	if table != "" {
		args = append(args, "table", table)
	}
	return c.Runner.Run(ctx, "ip", args...)
}

// ParsedRoutes разбирает таблицу маршрутизации по полям.
func (c *Collector) ParsedRoutes(ctx context.Context, table string) ([]Route, error) {
	raw, err := c.Routes(ctx, table)
	if err != nil {
		return nil, err
	}
	if table == "" {
		table = "main"
	}

	var out []Route
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		destinationIndex := 0
		routeType := "unicast"
		switch fields[0] {
		case "local", "broadcast", "multicast", "throw", "unreachable", "prohibit", "blackhole", "nat", "anycast":
			routeType = fields[0]
			destinationIndex = 1
		}
		if destinationIndex >= len(fields) {
			continue
		}
		r := Route{Type: routeType, Destination: fields[destinationIndex], Table: table, Raw: line, Origin: "boot"}

		for i := destinationIndex + 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					r.Gateway = fields[i+1]
				}
			case "dev":
				if i+1 < len(fields) {
					r.Interface = fields[i+1]
				}
			case "src":
				if i+1 < len(fields) {
					r.Source = fields[i+1]
				}
			case "metric":
				if i+1 < len(fields) {
					r.Metric = atoi(fields[i+1])
				}
			case "proto":
				if i+1 < len(fields) {
					r.Origin = fields[i+1]
					// Пока файл протоколов не записан, ядро отдаёт номер.
					switch r.Origin {
					case fmt.Sprint(config.RouteProto):
						r.Origin = config.RouteProtoName
					}
				}
			}
		}
		out = append(out, r)
	}
	return out, scanner.Err()
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// Rules отдаёт правила выбора таблиц маршрутизации — основу движка каналов.
func (c *Collector) Rules(ctx context.Context) (string, error) {
	return c.Runner.Run(ctx, "ip", "-4", "rule", "show")
}

// ConntrackCount возвращает число отслеживаемых соединений.
func (c *Collector) ConntrackCount() int64 {
	root := c.ProcNetfilter
	if root == "" {
		root = "/proc/sys/net/netfilter"
	}
	return readInt(filepath.Join(root, "nf_conntrack_count"))
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

package runtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/monitor"
	"github.com/netos-router/netos/internal/system"
	_ "modernc.org/sqlite"
)

const HistoryInterval = 30 * time.Second

type ClientCounter struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	RX      uint64 `json:"rx"`
	TX      uint64 `json:"tx"`
}
type clientBaseline struct {
	ClientCounter
	At time.Time
}
type DNSCount struct {
	Client string `json:"client"`
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
	First  int64  `json:"first"`
	Last   int64  `json:"last"`
}
type ClientHistory struct {
	Runner       system.Runner
	Collector    *Collector
	Current      func() *config.Config
	Extra        func(context.Context, *config.Config) []ClientCounter
	db           *sql.DB
	mu           sync.Mutex
	addresses    map[string]ClientCounter
	baseline     map[string]clientBaseline
	dns          map[string]*DNSCount
	enabled      bool
	problem      string
	dnsProblem   string
	limited      bool
	dnsCancel    context.CancelFunc
	lastPrune    time.Time
	lastPersist  time.Time
	liveUntil    time.Time
	liveBaseline map[string]clientBaseline
	liveSnapshot ClientLive
}

func NewClientHistory(path string, r system.Runner, c *Collector, current func() *config.Config) (*ClientHistory, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=3000; PRAGMA max_page_count=16384;
 CREATE TABLE IF NOT EXISTS traffic(at INTEGER,id TEXT,name TEXT,address TEXT,rx INTEGER,tx INTEGER,seconds REAL);
 CREATE INDEX IF NOT EXISTS traffic_time ON traffic(at);
 CREATE INDEX IF NOT EXISTS traffic_client_time ON traffic(id,at DESC);
 CREATE TABLE IF NOT EXISTS domains(at INTEGER,client TEXT,domain TEXT,n INTEGER,first INTEGER,last INTEGER);
 CREATE INDEX IF NOT EXISTS domains_time ON domains(at);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0600)
	return &ClientHistory{Runner: r, Collector: c, Current: current, db: db, addresses: map[string]ClientCounter{}, baseline: map[string]clientBaseline{}, dns: map[string]*DNSCount{}}, nil
}
func (h *ClientHistory) Close() error { return h.db.Close() }
func (h *ClientHistory) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last *config.Config
	var sampled time.Time
	for {
		current := h.Current()
		due := sampled.Add(h.sampleInterval(time.Now()))
		if !h.lastPersist.IsZero() && h.lastPersist.Add(HistoryInterval).Before(due) {
			due = h.lastPersist.Add(HistoryInterval)
		}
		if current != last || (current != nil && current.TrafficMonitor.Enabled && !time.Now().Add(50*time.Millisecond).Before(due)) {
			sampled = time.Now()
			h.sample(ctx)
			last = current
		}
		select {
		case <-ctx.Done():
			h.stopDNS()
			return
		case <-ticker.C:
			pruneInterval := time.Hour
			if current != nil && current.TrafficMonitor.Enabled {
				pruneInterval = 5 * time.Minute
			}
			if time.Since(h.lastPrune) >= pruneInterval {
				if err := h.prune(time.Now()); err != nil {
					h.setProblem("Не удалось очистить старую историю")
				}
			}
		}
	}
}
func (h *ClientHistory) stopDNS() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dnsCancel != nil {
		h.dnsCancel()
		h.dnsCancel = nil
	}
}
func (h *ClientHistory) identity(ctx context.Context, cfg *config.Config) map[string]ClientCounter {
	out := map[string]ClientCounter{}
	local := map[string]bool{}
	for _, n := range monitor.Interfaces(cfg) {
		local[n] = true
	}
	names := map[string]string{}
	add := func(addr, mac, name string) {
		mac = strings.ToLower(mac)
		if addr == "" || mac == "" {
			return
		}
		for _, known := range cfg.Clients {
			if strings.EqualFold(known.MAC, mac) && known.Name != "" {
				name = known.Name
				break
			}
		}
		if name == "" {
			name = names[mac]
		}
		if name == "" {
			name = addr
		}
		names[mac] = name
		out[addr] = ClientCounter{ID: "mac:" + mac, Name: name, Address: addr}
	}
	leases, _ := h.Collector.Leases()
	for _, l := range leases {
		if l.Expires.After(time.Now()) {
			add(l.IP, l.MAC, l.Hostname)
		}
	}
	raw, _ := h.Runner.Run(ctx, "ip", "-j", "neigh", "show")
	var neighbors []struct {
		Address string `json:"dst"`
		MAC     string `json:"lladdr"`
		Device  string `json:"dev"`
	}
	if json.Unmarshal([]byte(raw), &neighbors) == nil {
		for _, n := range neighbors {
			if local[n.Device] {
				add(n.Address, n.MAC, "")
			}
		}
	}
	for _, s := range cfg.VPNServers {
		if !s.Enabled {
			continue
		}
		for _, p := range s.Peers {
			if !p.Enabled {
				continue
			}
			addr := strings.Split(p.Address, "/")[0]
			if addr == "" {
				continue
			}
			out[addr] = ClientCounter{ID: "vpn:" + s.ID + ":" + p.ID, Name: p.Name + " · " + s.Name, Address: addr}
		}
	}
	return out
}

// nft's per-element counters include short-lived connections without polling
// conntrack. Hash size is bounded by the accounting rules, not connection count.
func ParseClientCounters(raw string) (map[string]ClientCounter, error) {
	var doc struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, err
	}
	result := map[string]ClientCounter{}
	for _, obj := range doc.Objects {
		var set struct {
			Name string            `json:"name"`
			Elem []json.RawMessage `json:"elem"`
		}
		if json.Unmarshal(obj["set"], &set) != nil {
			continue
		}
		if set.Name != "up4" && set.Name != "up6" && set.Name != "down4" && set.Name != "down6" {
			continue
		}
		for _, rawElem := range set.Elem {
			var wrapper struct {
				Elem struct {
					Val     string `json:"val"`
					Counter struct {
						Bytes uint64 `json:"bytes"`
					} `json:"counter"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(rawElem, &wrapper); err != nil {
				continue
			}
			e := wrapper.Elem
			if _, err := netip.ParseAddr(e.Val); err != nil {
				continue
			}
			v := result[e.Val]
			v.Address = e.Val
			if strings.HasPrefix(set.Name, "up") {
				v.TX += e.Counter.Bytes
			} else {
				v.RX += e.Counter.Bytes
			}
			result[e.Val] = v
		}
	}
	return result, nil
}
func (h *ClientHistory) sample(parent context.Context) {
	cfg := h.Current()
	if cfg == nil {
		return
	}
	enabled := cfg.TrafficMonitor.Enabled
	h.mu.Lock()
	h.enabled = enabled
	h.mu.Unlock()
	if !enabled {
		h.stopDNS()
		h.mu.Lock()
		h.baseline = map[string]clientBaseline{}
		h.liveBaseline = nil
		h.liveSnapshot = ClientLive{}
		h.liveUntil = time.Time{}
		h.lastPersist = time.Time{}
		h.dns = map[string]*DNSCount{}
		h.addresses = map[string]ClientCounter{}
		h.problem = ""
		h.dnsProblem = ""
		h.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	identities := h.identity(ctx, cfg)
	h.mu.Lock()
	h.addresses = identities
	if h.dnsCancel == nil {
		dnsCtx, stop := context.WithCancel(parent)
		h.dnsCancel = stop
		go h.watchDNS(dnsCtx)
	}
	h.mu.Unlock()
	raw, err := h.Runner.Run(ctx, "nft", "-j", "list", "table", "inet", monitor.Table)
	if err != nil {
		h.setProblem("Не удалось прочитать счётчики клиентов")
		return
	}
	counts, err := ParseClientCounters(raw)
	if err != nil {
		h.setProblem("Некорректный ответ счётчиков клиентов")
		return
	}
	samples := []ClientCounter{}
	for addr, v := range counts {
		known, ok := identities[addr]
		if !ok {
			known = ClientCounter{ID: "ip:" + addr, Name: addr, Address: addr}
		}
		known.RX = v.RX
		known.TX = v.TX
		samples = append(samples, known)
	}
	for addr, known := range identities {
		if _, ok := counts[addr]; !ok {
			samples = append(samples, known)
		}
	}
	if h.Extra != nil {
		samples = append(samples, h.Extra(ctx, cfg)...)
	}
	now := time.Now().UTC()
	h.publishLive(now, samples)
	if !h.lastPersist.IsZero() && now.Sub(h.lastPersist) < HistoryInterval {
		return
	}
	h.lastPersist = now
	if err = h.persist(now, samples); err != nil {
		h.setProblem("Не удалось сохранить историю: " + err.Error())
	} else {
		h.setProblem("")
	}
}
func (h *ClientHistory) setProblem(s string) { h.mu.Lock(); h.problem = s; h.mu.Unlock() }
func (h *ClientHistory) persist(now time.Time, values []ClientCounter) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	next := map[string]clientBaseline{}
	type delta struct {
		ClientCounter
		Seconds float64
	}
	deltas := map[string]delta{}
	// Baselines are per address and owner: DHCP reassignment never credits a new
	// owner with the previous owner's accumulated bytes.
	for _, v := range values {
		key := v.Address + "|" + v.ID
		old, ok := h.baseline[key]
		next[key] = clientBaseline{v, now}
		if !ok || now.Sub(old.At) > 2*HistoryInterval {
			continue
		}
		if v.RX < old.RX || v.TX < old.TX {
			continue
		}
		rx, txBytes := v.RX-old.RX, v.TX-old.TX
		d := deltas[v.ID]
		d.ID = v.ID
		d.Name = v.Name
		d.Address = v.Address
		d.RX += rx
		d.TX += txBytes
		if seconds := now.Sub(old.At).Seconds(); seconds > d.Seconds {
			d.Seconds = seconds
		}
		deltas[v.ID] = d
	}
	for _, d := range deltas {
		if _, err = tx.Exec("INSERT INTO traffic VALUES(?,?,?,?,?,?,?)", now.Unix(), d.ID, d.Name, d.Address, d.RX, d.TX, d.Seconds); err != nil {
			return err
		}
	}
	for _, d := range h.dns {
		if strings.HasPrefix(d.Client, "ip:") {
			if owner, ok := h.addresses[strings.TrimPrefix(d.Client, "ip:")]; ok {
				d.Client = owner.ID
			}
		}
		if _, err = tx.Exec("INSERT INTO domains VALUES(?,?,?,?,?,?)", now.Unix(), d.Client, d.Domain, d.Count, d.First, d.Last); err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	h.baseline = next
	h.dns = map[string]*DNSCount{}
	return nil
}
func (h *ClientHistory) AddDNS(at time.Time, addr, domain string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if len(domain) == 0 || len(domain) > 253 {
		return
	}
	if _, err := netip.ParseAddr(addr); err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.enabled {
		return
	}
	client, ok := h.addresses[addr]
	if !ok {
		ip, _ := netip.ParseAddr(addr)
		if ip.IsLoopback() {
			return
		}
		client = ClientCounter{ID: "ip:" + addr}
	}
	key := client.ID + "|" + domain
	d := h.dns[key]
	if d == nil {
		if len(h.dns) >= 4096 {
			h.limited = true
			return
		}
		d = &DNSCount{Client: client.ID, Domain: domain, First: at.Unix()}
		h.dns[key] = d
	}
	d.Count++
	d.Last = at.Unix()
}

type ClientTotal struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	RX      uint64 `json:"rx"`
	TX      uint64 `json:"tx"`
	Queries int64  `json:"queries"`
}
type ClientPoint struct {
	At int64   `json:"at"`
	ID string  `json:"id"`
	RX float64 `json:"rx_bps"`
	TX float64 `json:"tx_bps"`
}
type ClientReport struct {
	Enabled bool          `json:"enabled"`
	Problem string        `json:"problem,omitempty"`
	Limited bool          `json:"limited"`
	Clients []ClientTotal `json:"clients"`
	Points  []ClientPoint `json:"points"`
	Domains []DNSCount    `json:"domains"`
	From    int64         `json:"from"`
	To      int64         `json:"to"`
}

func (h *ClientHistory) Report(ctx context.Context, from, to time.Time, selected []string, details bool) (ClientReport, error) {
	h.mu.Lock()
	report := ClientReport{Enabled: h.enabled, Problem: h.problem, Limited: h.limited, Clients: []ClientTotal{}, Points: []ClientPoint{}, Domains: []DNSCount{}, From: from.Unix(), To: to.Unix()}
	if h.dnsProblem != "" {
		report.Problem = strings.TrimSpace(report.Problem + " " + h.dnsProblem)
	}
	h.mu.Unlock()
	rows, err := h.db.QueryContext(ctx, "SELECT t.id,(SELECT name FROM traffic WHERE id=t.id ORDER BY at DESC LIMIT 1),(SELECT address FROM traffic WHERE id=t.id ORDER BY at DESC LIMIT 1),SUM(t.rx),SUM(t.tx) FROM traffic t WHERE t.at>=? AND t.at<=? GROUP BY t.id ORDER BY SUM(t.rx+t.tx) DESC LIMIT 512", from.Unix(), to.Unix())
	if err != nil {
		return report, err
	}
	for rows.Next() {
		var c ClientTotal
		if err = rows.Scan(&c.ID, &c.Name, &c.Address, &c.RX, &c.TX); err != nil {
			rows.Close()
			return report, err
		}
		report.Clients = append(report.Clients, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return report, err
	}
	if len(selected) == 0 {
		for i, c := range report.Clients {
			if i == 5 {
				break
			}
			selected = append(selected, c.ID)
		}
	}
	if len(selected) > 16 {
		return report, fmt.Errorf("не более 16 клиентов")
	}
	if len(selected) == 0 {
		return report, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(selected)), ",")
	args := []any{from.Unix(), to.Unix()}
	for _, id := range selected {
		args = append(args, id)
	}
	step := int64(to.Sub(from).Seconds() / 400)
	if step < 30 {
		step = 30
	}
	query := fmt.Sprintf("SELECT (at/%d)*%d,id,SUM(rx)*8.0/MAX(SUM(seconds),1),SUM(tx)*8.0/MAX(SUM(seconds),1) FROM traffic WHERE at>=? AND at<=? AND id IN (%s) GROUP BY at/%d,id ORDER BY at", step, step, placeholders, step)
	rows, err = h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return report, err
	}
	for rows.Next() {
		var p ClientPoint
		if err = rows.Scan(&p.At, &p.ID, &p.RX, &p.TX); err != nil {
			rows.Close()
			return report, err
		}
		report.Points = append(report.Points, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return report, err
	}
	if details {
		rows, err = h.db.QueryContext(ctx, "SELECT client,domain,SUM(n),MIN(first),MAX(last) FROM domains WHERE at>=? AND at<=? AND client IN ("+placeholders+") GROUP BY client,domain ORDER BY SUM(n) DESC LIMIT 200", args...)
		if err != nil {
			return report, err
		}
		for rows.Next() {
			var d DNSCount
			if err = rows.Scan(&d.Client, &d.Domain, &d.Count, &d.First, &d.Last); err != nil {
				rows.Close()
				return report, err
			}
			report.Domains = append(report.Domains, d)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return report, err
		}
		rows, err = h.db.QueryContext(ctx, "SELECT client,SUM(n) FROM domains WHERE at>=? AND at<=? GROUP BY client", from.Unix(), to.Unix())
		if err != nil {
			return report, err
		}
		queries := map[string]int64{}
		for rows.Next() {
			var id string
			var n int64
			if err = rows.Scan(&id, &n); err != nil {
				rows.Close()
				return report, err
			}
			queries[id] = n
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return report, err
		}
		for i := range report.Clients {
			report.Clients[i].Queries = queries[report.Clients[i].ID]
		}
	}
	sort.Slice(report.Points, func(i, j int) bool { return report.Points[i].At < report.Points[j].At })
	return report, nil
}

// Retention also runs while collection is disabled; disabling is not permanent storage.
func (h *ClientHistory) prune(now time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	{
		for _, table := range []string{"traffic", "domains"} {
			if _, err = tx.Exec("DELETE FROM "+table+" WHERE at < ?", now.Add(-7*24*time.Hour).Unix()); err != nil {
				return err
			}
			limit := 200000
			if table == "domains" {
				limit = 50000
			}
			result, e := tx.Exec("DELETE FROM "+table+" WHERE rowid IN (SELECT rowid FROM "+table+" ORDER BY at DESC LIMIT -1 OFFSET ?)", limit)
			if e != nil {
				return e
			}
			if n, _ := result.RowsAffected(); n > 0 {
				h.limited = true
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	h.lastPrune = now
	return nil
}
func (h *ClientHistory) setDNSProblem(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.enabled {
		h.dnsProblem = s
	}
}

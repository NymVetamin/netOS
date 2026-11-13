package runtime

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"
)

// Cache only the bounded raw traffic samples, not responses or rounded ranges.
// Moving window edges and arbitrary periods therefore keep their exact meaning.
// The SQLite database remains authoritative; failed writes never enter the cache.
// Bound expanded samples, including compact idle batches. Above this budget
// use SQL aggregation rather than expanding seven days into resident memory.
const maxCachedTrafficRows = 262144
const maxCachedTrafficClients = 4096

type historyTrafficSample struct {
	at      int64
	rx, tx  uint64
	seconds float64
}

type historyTrafficClient struct {
	name, address string
	latest        int64
	samples       []historyTrafficSample
}

type historyTrafficCache struct {
	clients map[string]*historyTrafficClient
	rows    int
}

func (c *historyTrafficCache) add(at int64, v ClientCounter, seconds float64) {
	client := c.clients[v.ID]
	if client == nil {
		client = &historyTrafficClient{name: v.Name, address: v.Address, latest: at}
		c.clients[v.ID] = client
	}
	// As with the existing (id, at DESC) index, the first row wins timestamp ties.
	if at > client.latest {
		client.name, client.address, client.latest = v.Name, v.Address, at
	}
	client.samples = append(client.samples, historyTrafficSample{at, v.RX, v.TX, seconds})
	c.rows++
}

func (c *historyTrafficCache) prune(before int64) {
	for id, client := range c.clients {
		kept := client.samples[:0]
		for _, sample := range client.samples {
			if sample.at >= before {
				kept = append(kept, sample)
			} else {
				c.rows--
			}
		}
		client.samples = kept
		if len(kept) == 0 {
			delete(c.clients, id)
		}
	}
}

// Caller holds trafficMu, also held across persist/prune transactions, so a
// concurrent first read cannot omit or double-count a committed batch.
func (h *ClientHistory) loadTrafficCache(ctx context.Context) error {
	var count, idle int
	if err := h.db.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM traffic),(SELECT COALESCE(SUM(n),0) FROM traffic_idle)").Scan(&count, &idle); err != nil {
		return err
	}
	// Predominantly idle history is cheaper to aggregate as shared batches
	// than to expand on first open. Keep the original cache for active history.
	if count+idle > maxCachedTrafficRows || idle > count {
		h.trafficCacheBlocked = true
		return nil
	}
	cache := &historyTrafficCache{clients: make(map[string]*historyTrafficClient)}
	// Preserve the legacy rowid tie order, without sorting a UNION of all
	// expanded samples. The two bounded scans occur only when building cache.
	for _, query := range []string{
		"SELECT at,id,name,address,rx,tx,seconds FROM traffic ORDER BY rowid",
		"SELECT t.at,c.id,c.name,c.address,0,0,t.seconds FROM traffic_idle t,json_each(t.clients) j JOIN traffic_idle_clients c ON c.rowid=j.value ORDER BY t.rowid",
	} {
		rows, err := h.db.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		for rows.Next() {
			var at int64
			var v ClientCounter
			var seconds float64
			if err := rows.Scan(&at, &v.ID, &v.Name, &v.Address, &v.RX, &v.TX, &seconds); err != nil {
				rows.Close()
				return err
			}
			cache.add(at, v, seconds)
			if len(cache.clients) > maxCachedTrafficClients {
				rows.Close()
				h.trafficCacheBlocked = true
				return nil
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	h.trafficCache = cache
	return nil
}

func historySelection(clients []ClientTotal, selected []string) []string {
	if len(selected) != 0 {
		return selected
	}
	var result []string
	for i, client := range clients {
		if i == 5 {
			break
		}
		result = append(result, client.ID)
	}
	return result
}

func (h *ClientHistory) reportTraffic(ctx context.Context, from, to time.Time, selected []string, includePoints bool) (ClientReport, []string, error) {
	h.trafficMu.Lock()
	defer h.trafficMu.Unlock()
	report := ClientReport{Clients: []ClientTotal{}, Points: []ClientPoint{}}
	if err := ctx.Err(); err != nil {
		return report, selected, err
	}
	if h.trafficCache == nil && !h.trafficCacheBlocked {
		if err := h.loadTrafficCache(ctx); err != nil {
			return report, selected, err
		}
	}
	if h.trafficCache == nil {
		return h.reportTrafficSQL(ctx, from, to, selected, includePoints)
	}
	start, end := from.Unix(), to.Unix()
	for id, client := range h.trafficCache.clients {
		if err := ctx.Err(); err != nil {
			return report, selected, err
		}
		total := ClientTotal{ID: id, Name: client.name, Address: client.address}
		found := false
		for i, sample := range client.samples {
			if i%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return report, selected, err
				}
			}
			if sample.at < start || sample.at > end {
				continue
			}
			found = true
			if sample.rx > math.MaxInt64-total.RX || sample.tx > math.MaxInt64-total.TX {
				return report, selected, fmt.Errorf("integer overflow in traffic totals")
			}
			total.RX += sample.rx
			total.TX += sample.tx
		}
		if found {
			// SQLite promotes individual rx+tx expressions to REAL but may
			// reject an overflowing integer SUM. Preserve that rare behavior.
			if total.RX > math.MaxInt64-total.TX {
				return h.reportTrafficSQL(ctx, from, to, selected, includePoints)
			}
			report.Clients = append(report.Clients, total)
		}
	}
	sort.Slice(report.Clients, func(i, j int) bool {
		a, b := report.Clients[i], report.Clients[j]
		if a.RX+a.TX == b.RX+b.TX {
			return a.ID > b.ID
		}
		return a.RX+a.TX > b.RX+b.TX
	})
	if len(report.Clients) > 512 {
		report.Clients = report.Clients[:512]
	}
	selected = historySelection(report.Clients, selected)
	if len(selected) > 16 {
		return report, selected, fmt.Errorf("не более 16 клиентов")
	}
	if !includePoints {
		return report, selected, ctx.Err()
	}
	step := int64(to.Sub(from).Seconds() / 400)
	if step < 30 {
		step = 30
	}
	seen := make(map[string]bool)
	for _, id := range selected {
		if seen[id] {
			continue
		}
		seen[id] = true
		client := h.trafficCache.clients[id]
		if client == nil {
			continue
		}
		type bucket struct {
			rx, tx  uint64
			seconds float64
		}
		buckets := make(map[int64]bucket)
		for i, sample := range client.samples {
			if i%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return report, selected, err
				}
			}
			if sample.at < start || sample.at > end {
				continue
			}
			at := sample.at / step * step
			b := buckets[at]
			if sample.rx > math.MaxInt64-b.rx || sample.tx > math.MaxInt64-b.tx {
				return report, selected, fmt.Errorf("integer overflow in traffic bucket")
			}
			b.rx += sample.rx
			b.tx += sample.tx
			b.seconds += sample.seconds
			buckets[at] = b
		}
		for at, b := range buckets {
			seconds := math.Max(b.seconds, 1)
			report.Points = append(report.Points, ClientPoint{At: at, ID: id, RX: float64(b.rx) * 8 / seconds, TX: float64(b.tx) * 8 / seconds})
		}
	}
	sort.Slice(report.Points, func(i, j int) bool {
		a, b := report.Points[i], report.Points[j]
		if a.At == b.At {
			return a.ID < b.ID
		}
		return a.At < b.At
	})
	return report, selected, ctx.Err()
}

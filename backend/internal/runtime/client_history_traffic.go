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
// Retention caps storage at 200k rows every five minutes. Leave bounded room
// for batches between those prunes instead of rebuilding at each new sample.
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
	var count int
	if err := h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM traffic").Scan(&count); err != nil {
		return err
	}
	if count > maxCachedTrafficRows {
		h.trafficCacheBlocked = true
		return nil
	}
	rows, err := h.db.QueryContext(ctx, "SELECT at,id,name,address,rx,tx,seconds FROM traffic ORDER BY rowid")
	if err != nil {
		return err
	}
	defer rows.Close()
	cache := &historyTrafficCache{clients: make(map[string]*historyTrafficClient)}
	for rows.Next() {
		var at int64
		var v ClientCounter
		var seconds float64
		if err := rows.Scan(&at, &v.ID, &v.Name, &v.Address, &v.RX, &v.TX, &seconds); err != nil {
			return err
		}
		cache.add(at, v, seconds)
		if len(cache.clients) > maxCachedTrafficClients {
			h.trafficCacheBlocked = true
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
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

func (h *ClientHistory) reportTraffic(ctx context.Context, from, to time.Time, selected []string) (ClientReport, []string, error) {
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
		return h.reportTrafficSQL(ctx, from, to, selected)
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
				return h.reportTrafficSQL(ctx, from, to, selected)
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

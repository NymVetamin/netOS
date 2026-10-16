package runtime

import (
	"sort"
	"time"
)

const ClientLiveInterval = 5 * time.Second

type ClientLive struct {
	Enabled bool            `json:"enabled"`
	At      int64           `json:"at"`
	Clients []ClientCounter `json:"clients"`
	Points  []ClientPoint   `json:"points"`
}

// All viewers share one short lease and one sample. No per-request OS commands
// or database writes; the existing sampler returns to 30s after viewers leave.
func (h *ClientHistory) Live() ClientLive {
	h.mu.Lock()
	defer h.mu.Unlock()
	cfg := h.Current()
	if cfg == nil || !cfg.TrafficMonitor.Enabled {
		return ClientLive{}
	}
	h.liveUntil = time.Now().Add(15 * time.Second)
	result := h.liveSnapshot
	result.Enabled = true
	return result
}
func (h *ClientHistory) sampleInterval(now time.Time) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if now.Before(h.liveUntil) {
		return ClientLiveInterval
	}
	return HistoryInterval
}
func (h *ClientHistory) publishLive(now time.Time, values []ClientCounter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	next := map[string]clientBaseline{}
	totals := map[string]ClientCounter{}
	rates := map[string]ClientPoint{}
	for _, v := range values {
		key := v.Address + "|" + v.ID
		old, ok := h.liveBaseline[key]
		next[key] = clientBaseline{v, now}
		seconds := now.Sub(old.At).Seconds()
		if !ok || seconds <= 0 || seconds > 2*HistoryInterval.Seconds() || v.RX < old.RX || v.TX < old.TX {
			continue
		}
		item := totals[v.ID]
		item.ID = v.ID
		item.Name = v.Name
		item.Address = v.Address
		item.RX += v.RX - old.RX
		item.TX += v.TX - old.TX
		totals[v.ID] = item
		point := rates[v.ID]
		point.ID = v.ID
		point.At = now.Unix()
		point.RX += float64(v.RX-old.RX) * 8 / seconds
		point.TX += float64(v.TX-old.TX) * 8 / seconds
		rates[v.ID] = point
	}
	result := ClientLive{Enabled: true, At: now.Unix(), Clients: []ClientCounter{}, Points: []ClientPoint{}}
	ids := make([]string, 0, len(totals))
	for id := range totals {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := totals[ids[i]], totals[ids[j]]
		if a.RX+a.TX == b.RX+b.TX {
			return ids[i] < ids[j]
		}
		return a.RX+a.TX > b.RX+b.TX
	})
	if len(ids) > 512 {
		ids = ids[:512]
	}
	for _, id := range ids {
		item := totals[id]
		result.Clients = append(result.Clients, item)
		result.Points = append(result.Points, rates[id])
	}
	h.liveBaseline = next
	h.liveSnapshot = result
}

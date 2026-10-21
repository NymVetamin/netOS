package api

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/config"
	rt "github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

type realtimeValue struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	RX      uint64   `json:"rx"`
	TX      uint64   `json:"tx"`
	RXBPS   *float64 `json:"rx_bps"`
	TXBPS   *float64 `json:"tx_bps"`
	At      float64  `json:"at"`
	Seconds float64  `json:"seconds"`
}
type realtimeSnapshot struct {
	Sequence uint64          `json:"sequence"`
	At       float64         `json:"at"`
	Values   []realtimeValue `json:"values"`
	Problems []string        `json:"problems"`
}
type realtimeMonitor struct {
	mu       sync.Mutex
	until    time.Time
	running  bool
	changed  chan struct{}
	snapshot realtimeSnapshot
	// Below owned by the single sampler goroutine only.
	identities   map[string]rt.ClientCounter
	identitiesAt time.Time
	cfg          *config.Config
	previous     map[string]rt.ClientCounter
}

func (s *Server) handleRealtime(w http.ResponseWriter, r *http.Request) {
	if !anySection(r, false, "dashboard", "traffic") {
		writeError(w, 403, "нет доступа")
		return
	}
	m := &s.realtime
	m.mu.Lock()
	m.until = time.Now().Add(3 * time.Second)
	if !m.running {
		m.running = true
		m.changed = make(chan struct{})
		go s.runRealtime()
	}
	snapshot := m.snapshot
	changed := m.changed
	m.mu.Unlock()
	if raw := r.URL.Query().Get("after"); raw != "" {
		after, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, 400, "некорректный номер снимка")
			return
		}
		if after == snapshot.Sequence {
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return
			case <-changed:
			case <-timer.C:
			}
			m.mu.Lock()
			snapshot = m.snapshot
			m.mu.Unlock()
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, snapshot)
}
func (s *Server) runRealtime() {
	m := &s.realtime
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		m.mu.Lock()
		if time.Now().After(m.until) {
			m.running = false
			m.previous = nil
			m.snapshot = realtimeSnapshot{}
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		snapshot := s.collectRealtime(ctx)
		cancel()
		m.mu.Lock()
		snapshot.Sequence = m.snapshot.Sequence + 1
		m.snapshot = snapshot
		close(m.changed)
		m.changed = make(chan struct{})
		m.mu.Unlock()
		<-ticker.C
	}
}

func realtimeRates(values []rt.ClientCounter, previous map[string]rt.ClientCounter) ([]realtimeValue, map[string]rt.ClientCounter) {
	result := make([]realtimeValue, 0, len(values))
	next := map[string]rt.ClientCounter{}
	groups := map[string]int{}
	for _, v := range values {
		key := v.ID + "|" + v.Address
		if _, exists := next[key]; exists {
			continue
		}
		row := realtimeValue{ID: v.ID, Name: v.Name, RX: v.RX, TX: v.TX, At: float64(v.SampledAt.UnixNano()) / 1e9}
		if old, ok := previous[key]; ok {
			dt := v.SampledAt.Sub(old.SampledAt).Seconds()
			if dt > 0 && dt < 3 && v.RX >= old.RX && v.TX >= old.TX {
				rx := float64(v.RX-old.RX) * 8 / dt
				tx := float64(v.TX-old.TX) * 8 / dt
				row.RXBPS = &rx
				row.TXBPS = &tx
				row.Seconds = dt
			}
		}
		if index, ok := groups[v.ID]; ok {
			old := &result[index]
			old.RX += row.RX
			old.TX += row.TX
			if old.RXBPS == nil || row.RXBPS == nil {
				old.RXBPS = nil
				old.TXBPS = nil
			} else {
				*old.RXBPS += *row.RXBPS
				*old.TXBPS += *row.TXBPS
			}
		} else {
			groups[v.ID] = len(result)
			result = append(result, row)
		}
		next[key] = v
	}
	return result, next
}

func (s *Server) collectRealtime(ctx context.Context) realtimeSnapshot {
	m := &s.realtime
	cfg := s.Engine.Current()
	result := realtimeSnapshot{Problems: []string{}}
	values := []rt.ClientCounter{}
	interfaces, err := rt.RealtimeInterfaces()
	at := time.Now()
	if err != nil {
		result.Problems = append(result.Problems, "Не удалось прочитать интерфейсы")
	}
	for _, v := range interfaces {
		v.SampledAt = at
		values = append(values, v)
	}
	if cfg != nil && cfg.TrafficMonitor.Enabled && s.ClientHistory != nil {
		if cfg != m.cfg || time.Since(m.identitiesAt) > 30*time.Second {
			m.identities = s.ClientHistory.RealtimeIdentities(ctx, cfg)
			m.identitiesAt = time.Now()
			m.cfg = cfg
		}
		counters, err := s.ClientHistory.RealtimeCounters(ctx)
		at = time.Now()
		if err != nil {
			result.Problems = append(result.Problems, "Не удалось прочитать счётчики LAN")
		}
		for addr, v := range counters {
			identity, ok := m.identities[addr]
			if !ok {
				identity = rt.ClientCounter{ID: "ip:" + addr, Name: addr}
			}
			v.ID, v.Name, v.SampledAt = identity.ID, identity.Name, at
			values = append(values, v)
		}
		// Read fresh RPC counters; the 5s session cache must not masquerade as 1s data.
		for _, server := range cfg.VPNServers {
			if !server.Enabled || server.Type != "xray" {
				continue
			}
			counts, err := realtimeXrayCounters(ctx, vpnservers.XrayStatsSocket(server))
			at = time.Now()
			if err != nil {
				result.Problems = append(result.Problems, "Нет счётчиков VPN: "+server.Name)
				continue
			}
			xr, err := server.XrayConfig()
			if err != nil {
				continue
			}
			for _, peer := range server.Peers {
				if peer.Enabled {
					identity := server.ID + "/" + peer.ID
					if xr.Protocol == "socks" || xr.Protocol == "http" {
						identity = peer.Credentials["username"]
					}
					if identity == "" {
						continue
					}
					prefix := "user>>>" + identity + ">>>traffic>>>"
					values = append(values, rt.ClientCounter{ID: "vpn:" + server.ID + ":" + peer.ID, Name: peer.Name + " · " + server.Name, RX: counts[prefix+"downlink"], TX: counts[prefix+"uplink"], SampledAt: at})
				}
			}
		}
	}
	result.Values, m.previous = realtimeRates(values, m.previous)
	result.At = float64(time.Now().UnixNano()) / 1e9
	return result
}

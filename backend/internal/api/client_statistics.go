package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	netosruntime "github.com/netos-router/netos/internal/runtime"
)

func statisticsRange(r *http.Request) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	to := now
	from := to.Add(-24 * time.Hour)
	if raw := r.URL.Query().Get("from"); raw != "" {
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil {
			return from, to, e
		}
		from = time.Unix(n, 0)
		n, e = strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
		if e != nil {
			return from, to, e
		}
		to = time.Unix(n, 0)
	} else if raw := r.URL.Query().Get("minutes"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 10080 {
			return from, to, fmt.Errorf("период: от 1 минуты до 7 дней")
		}
		from = to.Add(-time.Duration(n) * time.Minute)
	} else if raw := r.URL.Query().Get("hours"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 168 {
			return from, to, fmt.Errorf("период: от 1 до 168 часов")
		}
		from = to.Add(-time.Duration(n) * time.Hour)
	}
	if !from.Before(to) || to.Sub(from) > 7*24*time.Hour || from.Before(now.Add(-7*24*time.Hour-time.Minute)) || to.After(now.Add(time.Minute)) {
		return from, to, fmt.Errorf("выберите период в пределах последних 7 дней")
	}
	return from, to, nil
}
func (s *Server) handleClientStatistics(w http.ResponseWriter, r *http.Request) {
	from, to, err := statisticsRange(r)
	if err != nil {
		writeError(w, 400, "%v", err)
		return
	}
	if s.ClientHistory == nil {
		writeError(w, 503, "сборщик истории недоступен")
		return
	}
	ids := []string{}
	if raw := r.URL.Query().Get("clients"); raw != "" {
		ids = strings.Split(raw, ",")
	}
	if len(ids) > 16 {
		writeError(w, 400, "выберите не более 16 клиентов")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	report, err := s.ClientHistory.Report(ctx, from, to, ids, r.URL.Query().Get("details") == "1")
	if err != nil {
		writeError(w, 500, "не удалось прочитать историю клиентов")
		return
	}
	writeJSON(w, 200, report)
}

// Xray terminates the client's connection. Reuse authenticated per-user counters
// instead of misattributing its outbound socket to an ordinary LAN client.
func (s *Server) ProxyClientCounters(ctx context.Context, cfg *config.Config) []netosruntime.ClientCounter {
	out := []netosruntime.ClientCounter{}
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type != "xray" {
			continue
		}
		rows := s.vpnClients(ctx, server)
		for _, r := range rows {
			if !r.TrafficKnown {
				continue
			}
			for _, p := range server.Peers {
				if p.ID == r.ID {
					out = append(out, netosruntime.ClientCounter{ID: "vpn:" + server.ID + ":" + p.ID, Name: p.Name + " · " + server.Name, Address: "xray:" + server.ID + ":" + p.ID, RX: r.Sent, TX: r.Received})
				}
			}
		}
	}
	return out
}

func (s *Server) handleClientLive(w http.ResponseWriter, r *http.Request) {
	if s.ClientHistory == nil {
		writeError(w, 503, "сборщик истории недоступен")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, s.ClientHistory.Live())
}

package api

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/subsys/channels"
)

func (s *Server) liveLinks(ctx context.Context, cfg *config.Config, stats []runtime.InterfaceStat) (wans, tunnels []map[string]any) {
	if cfg == nil {
		return nil, nil
	}
	up := map[string]bool{}
	for _, stat := range stats {
		up[stat.Name] = stat.Up
	}
	for _, wan := range cfg.WANs {
		if !wan.Enabled {
			continue
		}
		name := ""
		for _, iface := range cfg.Interfaces {
			if iface.ID == wan.Interface {
				name = iface.Name
				break
			}
		}
		if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
			name = "ppp-" + wan.ID
		}
		wans = append(wans, map[string]any{"id": wan.ID, "name": wan.Name, "interface": name, "up": up[name]})
	}
	for _, ch := range cfg.Channels {
		if !ch.Enabled || ch.Type == "direct" {
			continue
		}
		name := channels.InterfaceName(ch)
		active := up[name]
		if active && ch.Type == "wireguard" {
			active = s.recentWireGuardHandshake(ctx, name)
		}
		tunnels = append(tunnels, map[string]any{"id": ch.ID, "name": ch.Name, "interface": name, "up": active})
	}
	return wans, tunnels
}

func (s *Server) recentWireGuardHandshake(ctx context.Context, name string) bool {
	if s.Collector == nil || s.Collector.Runner == nil {
		return false
	}
	out, err := s.Collector.Runner.Run(ctx, "wg", "show", name, "latest-handshakes")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil && seconds > 0 && time.Since(time.Unix(seconds, 0)) < 3*time.Minute {
			return true
		}
	}
	return false
}

package routing

import (
	"context"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Only configured owners can suspend a route. An unknown device name is
// still passed to the kernel, so a typo cannot silently disable routing.
func splitRoutes(cfg *config.Config, includeBase bool) (base, tunnels []config.StaticRoute) {
	var owners map[string]bool
	for _, r := range cfg.Routing.Static {
		if !r.Enabled {
			continue
		}
		if r.Interface != "" && (r.Type == "" || r.Type == "unicast") {
			if owners == nil {
				owners = make(map[string]bool)
				for _, ch := range cfg.Channels {
					if name := config.ChannelInterface(ch); name != "" {
						owners[name] = ch.Enabled
					}
				}
				// A WG peer used as an exit shares the server's interface. Only the
				// server switch controls the lifetime of that device.
				for _, s := range cfg.VPNServers {
					if s.Type == "wireguard" {
						owners[fmt.Sprintf("wg-srv%d", s.Index)] = s.Enabled
					}
				}
			}
			if active, owned := owners[r.Interface]; owned {
				if active {
					tunnels = append(tunnels, r)
				}
				continue
			}
		}
		if includeBase {
			base = append(base, r)
		}
	}
	return
}

// TunnelRoutes finishes routing after the tunnel interfaces have been created.
// The early routing phase owns stale-route cleanup across both phases.
type TunnelRoutes struct{ Runner system.Runner }

func (*TunnelRoutes) Name() string                                     { return "tunnel-routes" }
func (*TunnelRoutes) Plan(_, _ *config.Config) ([]apply.Action, error) { return nil, nil } // reported by routing
func (t *TunnelRoutes) Apply(ctx context.Context, cfg *config.Config) error {
	_, routes := splitRoutes(cfg, false)
	live, err := t.snapshot(ctx, routes)
	if err != nil {
		return err
	}
	return New(t.Runner).installRoutes(ctx, routes, live)
}
func (t *TunnelRoutes) Health(ctx context.Context, cfg *config.Config) error {
	_, routes := splitRoutes(cfg, false)
	live, err := t.snapshot(ctx, routes)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if !staticRouteAlreadyApplied(live[routeFamily(r)][staticRouteKey(r)], r) {
			return fmt.Errorf("маршрут %s через %s не соответствует конфигурации", r.Destination, r.Interface)
		}
	}
	return nil
}
func (t *TunnelRoutes) snapshot(ctx context.Context, routes []config.StaticRoute) (map[string]map[string]string, error) {
	live := map[string]map[string]string{}
	for _, r := range routes {
		family := routeFamily(r)
		if live[family] != nil {
			continue
		}
		out, err := t.Runner.Run(ctx, "ip", family, "route", "show", "table", "all", "proto", "static")
		if err != nil {
			return nil, fmt.Errorf("чтение статических маршрутов (%s): %w", family, err)
		}
		lines := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != "" {
				lines[routeLineKey(line)] = line
			}
		}
		live[family] = lines
	}
	return live, nil
}

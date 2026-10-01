package netiface

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// pppDefaultRoute records the exact default route installed by a netOS PPP
// session. pppd owns the interface, but changing its metric can leave the old
// route in main after the session restarts. Never sweep other PPP routes.
type pppDefaultRoute struct {
	Interface string `json:"interface"`
	Metric    int    `json:"metric"`
}

func (s *WAN) pppRoutePath() string {
	if s.OwnedRoutePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.OwnedRoutePath), "owned-ppp-default-routes.json")
}

func (s *WAN) readPPPDefaultRoutes() ([]pppDefaultRoute, error) {
	path := s.pppRoutePath()
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение маршрутов PPP netOS: %w", err)
	}
	var routes []pppDefaultRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, fmt.Errorf("разбор маршрутов PPP netOS: %w", err)
	}
	return routes, nil
}

func (s *WAN) writePPPDefaultRoutes(routes []pppDefaultRoute) error {
	path := s.pppRoutePath()
	if path == "" {
		return nil
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Interface == routes[j].Interface {
			return routes[i].Metric < routes[j].Metric
		}
		return routes[i].Interface < routes[j].Interface
	})
	data, err := json.MarshalIndent(routes, "", "  ")
	if err != nil {
		return err
	}
	if _, err := system.WriteFileAtomicIfChanged(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("запись маршрутов PPP netOS: %w", err)
	}
	return nil
}

func pppRouteKey(route pppDefaultRoute) string {
	return route.Interface + "|" + strconv.Itoa(route.Metric)
}

// recoverPPPMetric reads only a generated netOS pppd options file. This
// seeds ownership when upgrading an existing installation without the ledger.
func recoverPPPMetric(path string) (int, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(string(data), "# Сгенерировано netOS.") {
		return 0, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "defaultroute-metric" {
			continue
		}
		metric, err := strconv.Atoi(fields[1])
		if err != nil || metric < 0 {
			return 0, fmt.Errorf("неверная прежняя метрика PPP в %s", path)
		}
		return metric, nil
	}
	return 0, nil
}

// Publish old and desired ownership before writing new PPP options. An apply
// interrupted after restart can then finish stale-route cleanup on retry.
func (s *WAN) preparePPPDefaultRouteOwnership(cfg *config.Config) ([]pppDefaultRoute, error) {
	previous, err := s.readPPPDefaultRoutes()
	if err != nil {
		return nil, err
	}
	wanted := make([]pppDefaultRoute, 0)
	union := map[string]pppDefaultRoute{}
	for _, route := range previous {
		union[pppRouteKey(route)] = route
	}
	for _, wan := range cfg.WANs {
		iface := PPPoEInterface(wan.ID)
		for _, path := range []string{pppoeConfPath(wan.ID), l2tpPPPPath(wan.ID)} {
			metric, err := recoverPPPMetric(path)
			if err != nil {
				return nil, err
			}
			if metric > 0 {
				route := pppDefaultRoute{Interface: iface, Metric: metric}
				union[pppRouteKey(route)] = route
			}
		}
		if wan.Enabled && (wan.Proto == "pppoe" || wan.Proto == "l2tp") {
			route := pppDefaultRoute{Interface: iface, Metric: wan.Metric}
			wanted = append(wanted, route)
			union[pppRouteKey(route)] = route
		}
	}
	if err := s.writePPPDefaultRoutes(pppRouteValues(union)); err != nil {
		return nil, err
	}
	return wanted, nil
}

func pppRouteValues(items map[string]pppDefaultRoute) []pppDefaultRoute {
	result := make([]pppDefaultRoute, 0, len(items))
	for _, route := range items {
		result = append(result, route)
	}
	return result
}

func (s *WAN) syncPPPDefaultRouteOwnership(ctx context.Context, wanted []pppDefaultRoute) error {
	previous, err := s.readPPPDefaultRoutes()
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, route := range wanted {
		keep[pppRouteKey(route)] = true
	}
	for _, route := range previous {
		if keep[pppRouteKey(route)] {
			continue
		}
		_, deleteErr := s.Runner.Run(ctx, "ip", "-4", "route", "del", "default", "dev", route.Interface, "metric", strconv.Itoa(route.Metric))
		if deleteErr != nil {
			// The PPP interface may already have disappeared when its unit was
			// stopped. Querying with "dev" then fails even though the old route
			// was removed by the kernel along with the interface.
			out, showErr := s.Runner.Run(ctx, "ip", "-4", "route", "show", "default")
			if showErr != nil || hasPPPDefaultRoute(out, route) {
				return fmt.Errorf("удаление старого PPP default dev %s metric %d: %w", route.Interface, route.Metric, deleteErr)
			}
		}
	}
	return s.writePPPDefaultRoutes(wanted)
}

func hasPPPDefaultRoute(output string, route pppDefaultRoute) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		iface, metric := "", -1
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "dev":
				iface = fields[i+1]
			case "metric":
				metric, _ = strconv.Atoi(fields[i+1])
			}
		}
		if iface == route.Interface && metric == route.Metric {
			return true
		}
	}
	return false
}

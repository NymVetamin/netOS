package routing

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

func (s *Subsystem) unusedTablesOnly(ctx context.Context, old, next *config.Config) bool {
	if !reflect.DeepEqual(enabledRoutes(old), enabledRoutes(next)) || !reflect.DeepEqual(enabledRules(old), enabledRules(next)) {
		return false
	}
	before, after := map[config.RouteTable]bool{}, map[config.RouteTable]bool{}
	for _, table := range old.Routing.Tables {
		before[table] = true
	}
	for _, table := range next.Routing.Tables {
		after[table] = true
	}
	changed := map[string]bool{}
	for table := range before {
		if !after[table] {
			changed[table.Name] = true
			changed[fmt.Sprint(table.Number)] = true
		}
	}
	for table := range after {
		if !before[table] {
			changed[table.Name] = true
			changed[fmt.Sprint(table.Number)] = true
		}
	}
	for _, cfg := range []*config.Config{old, next} {
		for _, route := range enabledRoutes(cfg) {
			if changed[route.Table] {
				return false
			}
		}
		for _, rule := range enabledRules(cfg) {
			if changed[rule.Table] {
				return false
			}
		}
	}
	for _, family := range []string{"-4", "-6"} {
		routes, err := s.Runner.Run(ctx, "ip", family, "route", "show", "table", "all")
		if err != nil || referencesChangedTable(routes, changed) {
			return false
		}
		rules, err := s.Runner.Run(ctx, "ip", family, "rule", "show")
		if err != nil || referencesChangedTable(rules, changed) {
			return false
		}
		if family == "-4" && !rulesAlreadyApplied(rules, old) {
			return false
		}
		// Prove that applying the unchanged static configuration will not also
		// migrate, replace, add or remove an unrelated owned route.
		static, err := s.Runner.Run(ctx, "ip", family, "route", "show", "table", "all", "proto", "static")
		if err != nil {
			return false
		}
		legacy, err := s.Runner.Run(ctx, "ip", family, "route", "show", "table", "all", "proto", fmt.Sprint(config.StaticRouteProto))
		if err != nil || strings.TrimSpace(legacy) != "" {
			return false
		}
		wanted := map[string]config.StaticRoute{}
		for _, route := range enabledRoutes(old) {
			if routeFamily(route) == family {
				wanted[staticRouteKey(route)] = route
			}
		}
		for _, line := range strings.Split(static, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			key := routeLineKey(line)
			route, ok := wanted[key]
			if !ok || !staticRouteAlreadyApplied(line, route) {
				return false
			}
			delete(wanted, key)
		}
		if len(wanted) > 0 {
			return false
		}
	}
	return true
}

func referencesChangedTable(out string, changed map[string]bool) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if (fields[i] == "table" || fields[i] == "lookup") && changed[fields[i+1]] {
				return true
			}
		}
	}
	return false
}

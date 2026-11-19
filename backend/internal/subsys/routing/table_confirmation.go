package routing

import (
	"context"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

type ruleSnapshot struct {
	output    string
	unchanged bool
}

func (s *Subsystem) unusedTablesOnly(ctx context.Context, old, next *config.Config, routes []config.StaticRoute, rules []config.RouteRule, readRules func() (ruleSnapshot, error)) bool {
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
	for _, route := range routes {
		if changed[route.Table] {
			return false
		}
	}
	for _, rule := range rules {
		if changed[rule.Table] {
			return false
		}
	}
	for _, family := range []string{"-4", "-6"} {
		liveRoutes, err := s.Runner.Run(ctx, "ip", family, "route", "show", "table", "all")
		if err != nil || referencesChangedTable(liveRoutes, changed) {
			return false
		}
		var rules string
		if family == "-4" {
			snapshot, err := readRules()
			if err != nil || !snapshot.unchanged {
				return false
			}
			rules = snapshot.output
		} else {
			rules, err = s.Runner.Run(ctx, "ip", family, "rule", "show")
		}
		if err != nil || referencesChangedTable(rules, changed) {
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
		for _, route := range routes {
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

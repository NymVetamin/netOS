package routing

import (
	"strings"

	"github.com/netos-router/netos/internal/config"
)

func staticRouteAlreadyApplied(line string, route config.StaticRoute) bool {
	if routeLineKey(line) != staticRouteKey(route) {
		return false
	}
	fields := strings.Fields(line)
	start := 1
	if route.Type == "blackhole" || route.Type == "unreachable" || route.Type == "prohibit" {
		start = 2
	}
	seen := map[string]bool{}
	for i := start; i < len(fields); i += 2 {
		if i+1 >= len(fields) || seen[fields[i]] {
			return false
		}
		seen[fields[i]] = true
		switch fields[i] {
		case "via", "table", "metric": // Included in the route key.
		case "dev":
			if start == 2 && fields[i+1] != "lo" {
				return false
			}
		case "proto":
			if fields[i+1] != "static" {
				return false
			}
		case "scope":
			want := "global"
			if route.Gateway == "" && (route.Type == "" || route.Type == "unicast") {
				want = "link"
			}
			if fields[i+1] != want {
				return false
			}
		case "pref":
			if fields[i+1] != "medium" || routeFamily(route) != "-6" {
				return false
			}
		default:
			return false // Preserve repair of MTU, src, onlink, multipath, etc.
		}
	}
	// The caller only supplies output filtered with proto static; iproute2
	// may omit that already-filtered attribute from individual lines.
	return true
}

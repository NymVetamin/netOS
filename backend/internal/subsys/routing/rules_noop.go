package routing

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// Unknown selectors and duplicate priorities deliberately fall back to the
// existing reconciliation. Only a completely matching owned ruleset is skipped.
func rulesAlreadyApplied(out string, cfg *config.Config) bool {
	matches, unique := compareRules(out, cfg, enabledRules(cfg))
	return matches && unique
}

// Health verifies every configured rule, including valid repeated priorities.
// Apply still rebuilds repeated priorities to preserve its ordering policy.
func compareRules(out string, cfg *config.Config, rules []config.RouteRule) (matches, unique bool) {
	if len(rules) == 0 {
		for line := range strings.Lines(out) {
			if p := leadingPriority(line); p >= rulePriorityBase && p <= rulePriorityMax {
				return false, true
			}
		}
		return true, true
	}
	tables := map[string]string{"local": "255", "main": "254", "default": "253"}
	for _, table := range cfg.Routing.Tables {
		tables[table.Name] = strconv.Itoa(table.Number)
	}
	type selectors struct{ from, to, mark, iface, table string }
	key := func(from, to, mark, iface, table string) selectors {
		prefix := func(value string) string {
			if value == "" || value == "all" || value == "0.0.0.0/0" {
				return "all"
			}
			if p, err := netip.ParsePrefix(value); err == nil {
				return p.Masked().String()
			}
			if a, err := netip.ParseAddr(value); err == nil && a.Is4() {
				return netip.PrefixFrom(a, 32).String()
			}
			return value
		}
		if mark != "" {
			parts := strings.Split(mark, "/")
			if len(parts) == 1 {
				parts = append(parts, "0xffffffff")
			}
			for i, value := range parts {
				if n, err := strconv.ParseUint(value, 0, 32); err == nil {
					parts[i] = strconv.FormatUint(n, 10)
				}
			}
			mark = strings.Join(parts, "/")
			if mark == "0/0" {
				mark = ""
			}
		}
		if number, ok := tables[table]; ok {
			table = number
		}
		return selectors{prefix(from), prefix(to), mark, iface, table}
	}
	type identity struct {
		priority  int
		selectors selectors
	}
	remaining := make(map[identity]int, len(rules))
	priorities := make(map[int]bool, len(rules))
	unique = true
	for _, rule := range rules {
		p := rule.Priority
		if p < rulePriorityBase || p > rulePriorityMax {
			p = rulePriorityBase + 100
		}
		if priorities[p] {
			unique = false
		}
		priorities[p] = true
		mark := rule.FwMark
		// For a bare zero iproute2 leaves the kernel mask unset. Its display
		// of an explicit 0/0xffffffff, however, is the bare word "0".
		if mark != "" && !strings.Contains(mark, "/") {
			if n, err := strconv.ParseUint(mark, 0, 32); err == nil && n == 0 {
				mark = ""
			}
		}
		remaining[identity{p, key(rule.From, rule.To, mark, rule.Interface, rule.Table)}]++
	}
	for line := range strings.SplitSeq(out, "\n") {
		p := leadingPriority(line)
		if p < rulePriorityBase || p > rulePriorityMax {
			continue
		}
		fields := strings.Fields(line)
		values := map[string]string{}
		for i := 1; i < len(fields); i += 2 {
			if i+1 >= len(fields) {
				return false, unique
			}
			name := fields[i]
			if name == "table" {
				name = "lookup"
			}
			switch name {
			case "from", "to", "fwmark", "iif", "lookup":
			default:
				return false, unique
			}
			if _, exists := values[name]; exists {
				return false, unique
			}
			values[name] = fields[i+1]
			if name == "iif" && i+2 < len(fields) && fields[i+2] == "[detached]" {
				i++
			}
		}
		if values["from"] == "" || values["lookup"] == "" {
			return false, unique
		}
		id := identity{p, key(values["from"], values["to"], values["fwmark"], values["iif"], values["lookup"])}
		switch remaining[id] {
		case 0:
			return false, unique
		case 1:
			delete(remaining, id)
		default:
			remaining[id]--
		}
	}
	return len(remaining) == 0, unique
}

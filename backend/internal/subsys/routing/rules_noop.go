package routing

import (
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// Unknown selectors and duplicate priorities deliberately fall back to the
// existing reconciliation. Only a completely matching owned ruleset is skipped.
func rulesAlreadyApplied(out string, cfg *config.Config) bool {
	tables := map[string]string{"local": "255", "main": "254", "default": "253"}
	for _, table := range cfg.Routing.Tables {
		tables[table.Name] = strconv.Itoa(table.Number)
	}
	key := func(from, to, mark, iface, table string) string {
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
				base := 10
				if strings.HasPrefix(value, "0x") {
					base = 16
					value = value[2:]
				}
				if n, err := strconv.ParseUint(value, base, 32); err == nil {
					parts[i] = strconv.FormatUint(n, 10)
				}
			}
			mark = strings.Join(parts, "/")
		}
		if number, ok := tables[table]; ok {
			table = number
		}
		return fmt.Sprintf("%s|%s|%s|%s|%s", prefix(from), prefix(to), mark, iface, table)
	}
	want, live := map[int]string{}, map[int]string{}
	for _, rule := range enabledRules(cfg) {
		p := rule.Priority
		if p < rulePriorityBase || p > rulePriorityMax {
			p = rulePriorityBase + 100
		}
		if _, exists := want[p]; exists {
			return false
		}
		want[p] = key(rule.From, rule.To, rule.FwMark, rule.Interface, rule.Table)
	}
	for _, line := range strings.Split(out, "\n") {
		p := leadingPriority(line)
		if p < rulePriorityBase || p > rulePriorityMax {
			continue
		}
		if _, exists := live[p]; exists {
			return false
		}
		fields := strings.Fields(line)
		values := map[string]string{}
		if len(fields)%2 != 1 {
			return false
		}
		for i := 1; i+1 < len(fields); i += 2 {
			name := fields[i]
			switch name {
			case "from", "to", "fwmark", "iif", "lookup":
			default:
				return false
			}
			if _, exists := values[name]; exists {
				return false
			}
			values[name] = fields[i+1]
		}
		if values["from"] == "" || values["lookup"] == "" {
			return false
		}
		live[p] = key(values["from"], values["to"], values["fwmark"], values["iif"], values["lookup"])
	}
	return reflect.DeepEqual(want, live)
}

package api

import (
	"net/http"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/firewall"
)

type liveFirewallChain struct {
	Name     string   `json:"name"`
	Policy   string   `json:"policy"`
	Counters string   `json:"counters"`
	Rules    []string `json:"rules"`
}
type liveFirewallTable struct {
	Name   string              `json:"name"`
	Chains []liveFirewallChain `json:"chains"`
}
type liveFirewallFamily struct {
	Family string              `json:"family"`
	Tables []liveFirewallTable `json:"tables"`
	Error  string              `json:"error,omitempty"`
}

// Keep unknown extensions and foreign rules verbatim; never infer a missing chain.
func parseLiveFirewall(raw string) []liveFirewallTable {
	tables := []liveFirewallTable{}
	var table *liveFirewallTable
	var chainIndex map[string]int
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			tables = append(tables, liveFirewallTable{Name: line[1:], Chains: []liveFirewallChain{}})
			table = &tables[len(tables)-1]
			chainIndex = make(map[string]int)
			continue
		}
		if line == "COMMIT" {
			table = nil
			continue
		}
		if table == nil || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line[1:])
			if len(fields) < 3 {
				continue
			}
			if _, found := chainIndex[fields[0]]; !found {
				chainIndex[fields[0]] = len(table.Chains)
			}
			table.Chains = append(table.Chains, liveFirewallChain{Name: fields[0], Policy: fields[1], Counters: fields[2], Rules: []string{}})
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "[") {
			fields = fields[1:]
		}
		if len(fields) < 2 || fields[0] != "-A" {
			continue
		}
		if i, found := chainIndex[fields[1]]; found {
			table.Chains[i].Rules = append(table.Chains[i].Rules, line)
		}
	}
	return tables
}

// Preview uses the same generator as Apply, but never saves or executes anything.
func (s *Server) handleFirewallPreview(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := readJSON(r, &cfg); err != nil {
		writeError(w, 400, "не удалось прочитать конфигурацию")
		return
	}
	if roleOf(r) == "limited" {
		previous := s.requestConfig(r)
		if previous == nil {
			writeError(w, 503, "конфигурация недоступна")
			return
		}
		merged, err := mergeScopedConfig(r, previous, &cfg)
		if err != nil {
			writeError(w, 403, "%v", err)
			return
		}
		cfg = *merged
	}
	rules, err := firewall.Build(&cfg)
	if err != nil {
		writeError(w, 400, "%v", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"families": []liveFirewallFamily{
		{Family: "IPv4", Tables: parseLiveFirewall(rules.IPv4)},
		{Family: "IPv6", Tables: parseLiveFirewall(rules.IPv6)},
	}, "rule_ids": rules.RuleIDs})
}

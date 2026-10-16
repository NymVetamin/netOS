package api

import (
	"github.com/netos-router/netos/internal/system"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			tables = append(tables, liveFirewallTable{Name: line[1:], Chains: []liveFirewallChain{}})
			table = &tables[len(tables)-1]
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
		for i := range table.Chains {
			if table.Chains[i].Name == fields[1] {
				table.Chains[i].Rules = append(table.Chains[i].Rules, line)
				break
			}
		}
	}
	return tables
}

var firewallComment = regexp.MustCompile(`--comment\s+("(?:\\.|[^"\\])*"|\S+)`)

func liveRuleComment(line string) string {
	m := firewallComment.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	if strings.HasPrefix(m[1], `"`) {
		v, e := strconv.Unquote(m[1])
		if e == nil {
			return v
		}
	}
	return m[1]
}
func (s *Server) handleLiveFirewall(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 5 * time.Second}
	}
	families := []liveFirewallFamily{}
	for _, item := range []struct{ family, command string }{{"IPv4", "iptables-save"}, {"IPv6", "ip6tables-save"}} {
		out, err := runner.Run(r.Context(), item.command, "-c")
		f := liveFirewallFamily{Family: item.family, Tables: []liveFirewallTable{}}
		if err != nil {
			f.Error = "Не удалось прочитать " + item.family + ": " + err.Error()
		} else {
			f.Tables = parseLiveFirewall(out)
		}
		families = append(families, f)
	}
	// Link saved rule names using the applied configuration, never the UI draft.
	comments := map[string]string{}
	for _, f := range families {
		for _, t := range f.Tables {
			for _, c := range t.Chains {
				for _, line := range c.Rules {
					comments[line] = liveRuleComment(line)
				}
			}
		}
	}
	sources := map[string]string{}
	if s.Engine != nil && s.Engine.Current() != nil {
		cfg := s.Engine.Current()
		for _, rule := range cfg.Firewall.Rules {
			sources[rule.Name] = "firewall"
		}
		for _, rule := range cfg.Firewall.NAT {
			sources[rule.Name] = "firewall"
			if rule.System && rule.Direction != "destination" && rule.Source == "" && rule.ToSource == "" {
				for _, wan := range cfg.WANs {
					name := cfg.InterfaceName(wan.Interface)
					if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
						name = "ppp-" + wan.ID
					}
					if name == rule.Interface {
						sources[rule.Name] = "network"
					}
				}
			}
		}
		for _, server := range cfg.VPNServers {
			sources["VPN-сервер «"+server.Name+"»"] = "vpn-servers"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"families": families, "sources": sources, "comments": comments, "captured_at": time.Now().UTC().Format(time.RFC3339)})
}

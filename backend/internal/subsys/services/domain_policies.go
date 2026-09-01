package services

import (
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/policy"
)

const policyDNSBackendPort = 5355

func hasKernelDomainPolicies(cfg *config.Config) bool {
	if cfg == nil || !cfg.DNS.Enabled {
		return false
	}
	xrayServers := map[string]bool{}
	for _, server := range cfg.VPNServers {
		if server.Type == "xray" {
			xrayServers[server.ID] = true
		}
	}
	for _, item := range cfg.Policies {
		if item.Enabled && len(item.Domains) > 0 && !xrayServers[item.VPNServer] {
			return true
		}
	}
	return false
}

func renderDomainPolicyIPSets(cfg *config.Config) []string {
	type rule struct {
		id      string
		domains []string
	}
	xrayServers := map[string]bool{}
	for _, server := range cfg.VPNServers {
		if server.Type == "xray" {
			xrayServers[server.ID] = true
		}
	}
	var rules []rule
	for _, item := range cfg.Policies {
		if !item.Enabled || len(item.Domains) == 0 || xrayServers[item.VPNServer] {
			continue
		}
		domains := make([]string, 0, len(item.Domains))
		for _, raw := range item.Domains {
			domain := strings.Trim(strings.ToLower(raw), ".")
			if domain != "" {
				domains = append(domains, domain)
			}
		}
		sort.Strings(domains)
		rules = append(rules, rule{id: item.ID, domains: domains})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].id < rules[j].id })
	var out []string
	for _, item := range rules {
		if len(item.domains) == 0 {
			continue
		}
		out = append(out, "ipset=/"+strings.Join(item.domains, "/")+"/"+policy.IPv4SetName(item.id))
	}
	return out
}

func backendLocalDNSNeeded(cfg *config.Config) bool {
	return localDNSNeeded(cfg) && !hasKernelDomainPolicies(cfg)
}

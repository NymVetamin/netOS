package firewall

import "github.com/netos-router/netos/internal/config"

// Keep the existing service exceptions when output can be denied. With an
// accepting policy and no manual output denies, these ACCEPTs change nothing.
// Conservatively retain exceptions for conditional/zone-specific denies too.
func needsServiceOutputAccept(c *config.Config) bool {
	if c.Firewall.OutputPolicy != "" && c.Firewall.OutputPolicy != "accept" {
		return true
	}
	for _, r := range c.Firewall.Rules {
		if r.Enabled && (r.Flow == "out" || r.Flow == "any") && (r.Action == "drop" || r.Action == "reject") {
			return true
		}
	}
	return false
}

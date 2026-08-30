package config

import "testing"

func TestValidateDDNSProviderRequirements(t *testing.T) {
	cfg := Default()
	cfg.DDNS = DDNS{Enabled: true, Provider: "cloudflare", Hostname: "bad name", AddressSource: "interface", Interval: 10}
	result := cfg.Validate()
	wanted := map[string]bool{"ddns.hostname": false, "ddns.interval": false, "ddns.wan": false, "ddns": false}
	for _, problem := range result.Problems {
		if _, ok := wanted[problem.Path]; ok {
			wanted[problem.Path] = true
		}
	}
	for path, found := range wanted {
		if !found {
			t.Errorf("missing validation problem %s: %#v", path, result.Problems)
		}
	}
}

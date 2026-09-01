package config

import "testing"

func TestDNSBlocklistValidationMatrix(t *testing.T) {
	tests := []struct {
		name string
		list Blocklist
		dns  bool
		path string
	}{
		{"valid enabled", Blocklist{ID: "ads", Name: "Ads", URL: "https://lists.example/hosts.txt", Enabled: true}, true, ""},
		{"disabled placeholder", Blocklist{ID: "ads"}, false, ""},
		{"missing name", Blocklist{ID: "ads", URL: "https://lists.example/hosts", Enabled: true}, true, "dns.blocklists[0].name"},
		{"missing URL", Blocklist{ID: "ads", Name: "Ads", Enabled: true}, true, "dns.blocklists[0].url"},
		{"plain HTTP", Blocklist{ID: "ads", Name: "Ads", URL: "http://lists.example/hosts", Enabled: true}, true, "dns.blocklists[0].url"},
		{"credentials", Blocklist{ID: "ads", Name: "Ads", URL: "https://user:pass@lists.example/hosts", Enabled: true}, true, "dns.blocklists[0].url"},
		{"fragment", Blocklist{ID: "ads", Name: "Ads", URL: "https://lists.example/hosts#part", Enabled: true}, true, "dns.blocklists[0].url"},
		{"control", Blocklist{ID: "ads", Name: "Ads\nnext", URL: "https://lists.example/hosts", Enabled: true}, true, "dns.blocklists[0].name"},
		{"DNS disabled", Blocklist{ID: "ads", Name: "Ads", URL: "https://lists.example/hosts", Enabled: true}, false, "dns.blocklists[0].enabled"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.DNS.Enabled = tc.dns
			if tc.dns {
				cfg.DNS.Provider = "dnsmasq"
				cfg.Components = append(cfg.Components, Component{ID: "dnsmasq", Installed: true})
			}
			cfg.DNS.Blocklists = []Blocklist{tc.list}
			result := cfg.Validate()
			if tc.path == "" {
				if result.HasErrors() {
					t.Fatalf("unexpected problems: %+v", result.Problems)
				}
				return
			}
			if !hasErrorAt(result, tc.path) {
				t.Fatalf("missing error at %s: %+v", tc.path, result.Problems)
			}
		})
	}
}

func TestDNSBlocklistRejectsDuplicateURL(t *testing.T) {
	cfg := Default()
	cfg.DNS.Enabled = true
	cfg.DNS.Provider = "dnsmasq"
	cfg.Components = append(cfg.Components, Component{ID: "dnsmasq", Installed: true})
	cfg.DNS.Blocklists = []Blocklist{
		{ID: "ads", Name: "Ads", URL: "https://lists.example/hosts", Enabled: true},
		{ID: "trackers", Name: "Trackers", URL: "https://lists.example/hosts", Enabled: true},
	}
	if result := cfg.Validate(); !hasErrorAt(result, "dns.blocklists[1].url") {
		t.Fatalf("duplicate URL accepted: %+v", result.Problems)
	}
}

package config

import "testing"

func TestValidationWarnsThatPPPUplinkGetsNoIPv6(t *testing.T) {
	for _, tc := range []struct {
		proto, mode string
		enabled     bool
		warn        bool
	}{
		{"pppoe", "passthrough", true, true},
		{"l2tp", "passthrough", true, true},
		{"pppoe", "off", true, false},
		{"pppoe", "passthrough", false, false},
		{"dhcp", "passthrough", true, false},
	} {
		cfg := Default()
		cfg.IPv6.Mode = tc.mode
		cfg.Interfaces = []Interface{{ID: "eth0", Name: "eth0", Type: "physical", Enabled: true}}
		cfg.WANs = []WAN{{ID: "wan1", Index: 1, Name: "WAN", Interface: "eth0", Enabled: tc.enabled, Proto: tc.proto,
			Username: "user", Password: "password", Server: "vpn.example.com", Metric: 100}}
		warned := false
		for _, p := range cfg.Validate().Problems {
			if p.Severity == "warning" && p.Path == "wans[0].proto" {
				warned = true
			}
		}
		if warned != tc.warn {
			t.Errorf("%s/%s enabled=%v: warning=%v, want %v", tc.proto, tc.mode, tc.enabled, warned, tc.warn)
		}
	}
}

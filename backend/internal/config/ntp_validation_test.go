package config

import "testing"

func TestNTPValidationRejectsUnsafeServers(t *testing.T) {
	for _, servers := range [][]string{
		{},
		{"pool.example\nInjected=yes"},
		{"pool.example", "POOL.EXAMPLE"},
		{"1", "2", "3", "4", "5", "6", "7", "8", "9"},
	} {
		cfg := Default()
		cfg.System.NTP.Enabled = true
		cfg.System.NTP.Servers = servers
		if result := cfg.Validate(); !hasErrorAt(result, "system.ntp.servers") {
			t.Fatalf("unsafe NTP list accepted: %#v", servers)
		}
	}
}

func TestNTPValidationAllowsHostnamesAndAddresses(t *testing.T) {
	cfg := Default()
	cfg.System.NTP.Servers = []string{"time.example.org", "192.0.2.123", "2001:db8::123"}
	if result := cfg.Validate(); hasErrorAt(result, "system.ntp.servers") {
		t.Fatalf("valid NTP servers rejected: %#v", result.Problems)
	}
}

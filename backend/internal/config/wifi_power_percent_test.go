package config

import "testing"

func TestWiFiPercentAndAutoChannel(t *testing.T) {
	cfg := validWiFiSecurityConfig()
	cfg.WiFi[0].Channel = 0
	cfg.WiFi[0].PowerPercent = 50
	if r := cfg.Validate(); r.HasErrors() {
		t.Fatalf("valid percent/ACS rejected: %+v", r.Problems)
	}
	for _, v := range []int{-1, 101} {
		cfg.WiFi[0].PowerPercent = v
		if !cfg.Validate().HasErrors() {
			t.Fatal("invalid percent accepted")
		}
	}
	cfg.WiFi[0].PowerPercent = 50
	cfg.WiFi[0].TxPower = 20
	if !cfg.Validate().HasErrors() {
		t.Fatal("ambiguous power accepted")
	}
}

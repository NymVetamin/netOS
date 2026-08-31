package config

import (
	"fmt"
	"testing"
)

func validWiFiSecurityConfig() *Config {
	cfg := Default()
	cfg.Components = []Component{{ID: "hostapd", Installed: true}}
	cfg.Interfaces = []Interface{{ID: "lan", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []Network{{ID: "home", Name: "Home", Interface: "lan", RouterAddress: "192.168.10.1/24", Zone: "lan", Enabled: true}}
	cfg.WiFi = []WiFiRadio{{
		ID: "radio", Device: "wlan0", Enabled: true, Band: "5", Channel: 36, Width: 80, Country: "RU",
		SSIDs: []WiFiSSID{{ID: "main", SSID: "netOS", Enabled: true, Security: "wpa2/wpa3", Password: "safe-password", Network: "home"}},
	}}
	return cfg
}

func TestWiFiRejectsHostapdImpossibleCombinations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*WiFiRadio)
	}{
		{"channel 14 with HT", func(r *WiFiRadio) { r.Band, r.Channel, r.Width = "2.4", 14, 20 }},
		{"non-primary 5 GHz channel", func(r *WiFiRadio) { r.Channel = 37 }},
		{"wide channel outside a block", func(r *WiFiRadio) { r.Channel, r.Width = 165, 80 }},
		{"non-letter country", func(r *WiFiRadio) { r.Country = "A[" }},
		{"BSS interface name overflow", func(r *WiFiRadio) {
			r.Device = "abcdefghijkl"
			for i := 0; i < 11; i++ {
				r.SSIDs = append(r.SSIDs, WiFiSSID{ID: fmt.Sprintf("guest%d", i), SSID: fmt.Sprintf("guest%d", i), Enabled: true, Security: "open", Network: "home"})
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validWiFiSecurityConfig()
			tc.mutate(&cfg.WiFi[0])
			if result := cfg.Validate(); !result.HasErrors() {
				t.Fatal("invalid Wi-Fi configuration was accepted")
			}
		})
	}
}

func TestWiFiAcceptsStandardPrimaryChannels(t *testing.T) {
	for _, channel := range []int{36, 40, 44, 48, 100, 144, 149, 161} {
		cfg := validWiFiSecurityConfig()
		cfg.WiFi[0].Channel = channel
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("channel %d rejected: %+v", channel, result.Problems)
		}
	}
}

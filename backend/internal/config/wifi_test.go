package config

import "testing"

func validWiFiConfig() *Config {
	cfg := Default()
	cfg.Components = []Component{{ID: "hostapd", Installed: true}}
	cfg.Interfaces = []Interface{{ID: "lan", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []Network{{ID: "home", Name: "Home", Interface: "lan", RouterAddress: "192.168.10.1/24", Zone: "lan", Enabled: true}}
	cfg.WiFi = []WiFiRadio{{
		ID: "radio", Device: "wlan0", Enabled: true, Band: "5", Channel: 36, Width: 80, Country: "RU",
		SSIDs: []WiFiSSID{{ID: "main", SSID: "netOS", Enabled: true, Security: "wpa2/wpa3", Password: "strong-password", Network: "home"}},
	}}
	return cfg
}

func TestWiFiValidation(t *testing.T) {
	cfg := validWiFiConfig()
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" {
			t.Fatalf("valid Wi-Fi config rejected: %+v", p)
		}
	}
	cfg.WiFi[0].SSIDs[0].Password = "short"
	if !cfg.Validate().HasErrors() {
		t.Fatal("short WPA password accepted")
	}
}

func TestWiFiRejectsConfigInjection(t *testing.T) {
	cfg := validWiFiConfig()
	cfg.WiFi[0].SSIDs[0].SSID = "safe\ninterface=eth0"
	if !cfg.Validate().HasErrors() {
		t.Fatal("newline in SSID accepted")
	}
}

package wifi

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestRenderEveryBandWidthSecurityAndSSIDFlag(t *testing.T) {
	cfg := wifiConfig()
	radio := cfg.WiFi[0]
	radio.Band, radio.Channel, radio.Width, radio.TxPower = "2.4", 11, 40, 0
	radio.SSIDs = []config.WiFiSSID{
		{ID: "open", SSID: "Open", Enabled: true, Security: "open", Network: "home"},
		{ID: "wpa2", SSID: "WPA2", Enabled: true, Security: "wpa2", Password: "password2", Network: "home", Hidden: true},
		{ID: "wpa3", SSID: "WPA3", Enabled: true, Security: "wpa3", Password: "password3", Network: "home", Isolate: true},
		{ID: "mixed", SSID: "Mixed", Enabled: true, Security: "wpa2/wpa3", Password: "password4", Network: "home", Hidden: true, Isolate: true},
		{ID: "off", SSID: "Disabled", Enabled: false, Security: "open", Network: "home"},
	}
	out, err := RenderRadio(radio, cfg)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, wanted := range []string{
		"hw_mode=g", "ht_capab=[HT40-]", "ssid=Open", "auth_algs=1", "wpa=0",
		"bss=wlan0-n1", "ssid=WPA2", "wpa_key_mgmt=WPA-PSK", "wpa_passphrase=password2", "ignore_broadcast_ssid=1",
		"bss=wlan0-n2", "ssid=WPA3", "wpa_key_mgmt=SAE", "sae_password=password3", "ap_isolate=1",
		"bss=wlan0-n3", "ssid=Mixed", "wpa_key_mgmt=WPA-PSK SAE", "ieee80211w=1",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("render lacks %q:\n%s", wanted, text)
		}
	}
	if strings.Contains(text, "Disabled") || strings.Contains(text, "ieee80211ac=1") || strings.Contains(text, "vht_oper_chwidth") {
		t.Fatalf("2.4 GHz/disabled SSID leaked unwanted configuration:\n%s", text)
	}
}

func TestRenderRejectsNoSSIDAndMissingBridge(t *testing.T) {
	cfg := wifiConfig()
	radio := cfg.WiFi[0]
	for i := range radio.SSIDs {
		radio.SSIDs[i].Enabled = false
	}
	if _, err := RenderRadio(radio, cfg); err == nil || !strings.Contains(err.Error(), "нет включённых") {
		t.Fatalf("empty radio render error=%v", err)
	}
	radio.SSIDs[0].Enabled = true
	radio.SSIDs[0].Network = "missing"
	if _, err := RenderRadio(radio, cfg); err == nil || !strings.Contains(err.Error(), "не найден") {
		t.Fatalf("missing bridge render error=%v", err)
	}
}

func TestChannelGeometryEveryBranch(t *testing.T) {
	for _, tc := range []struct {
		band    string
		channel int
		want    string
	}{
		{"2.4", 1, "+"}, {"2.4", 8, "-"},
		{"5", 36, "+"}, {"5", 40, "-"}, {"5", 165, "-"}, {"5", 173, "-"},
	} {
		if got := secondaryChannelDirection(tc.band, tc.channel); got != tc.want {
			t.Errorf("direction %s/%d=%q want %q", tc.band, tc.channel, got, tc.want)
		}
	}
	for _, tc := range []struct{ channel, center int }{
		{36, 42}, {52, 58}, {100, 106}, {116, 122}, {132, 138}, {149, 155}, {165, 165},
	} {
		if got := center80(tc.channel); got != tc.center {
			t.Errorf("center80(%d)=%d want %d", tc.channel, got, tc.center)
		}
	}
}

func TestRadioInfoParserUsesExactFieldsAndNormalizesCRLF(t *testing.T) {
	valid := "Interface wlan0\r\n\tssid exact name\r\n\ttype AP\r\n\tchannel 36 (5180 MHz), width: 80 MHz\r\n\ttxpower 18.00 dBm\r\n"
	if !radioInfoMatches(valid, "wlan0", 36, "exact name") || !txPowerMatches(valid, 18) {
		t.Fatal("valid iw info was not recognized")
	}
	if radioInfoMatches(valid, "wlan", 36, "exact") || txPowerMatches(valid, 17) || txPowerMatches("txpower broken", 18) {
		t.Fatal("substring or invalid txpower was accepted")
	}
}

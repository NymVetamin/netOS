package config

import (
	"strings"
	"testing"
)

func TestUnimplementedFeaturesFailLoudly(t *testing.T) {
	cfg := Default()
	cfg.Channels = append(cfg.Channels, Channel{ID: "xray", Index: 1, Name: "VPN", Enabled: true, Type: "xray", Mode: "tun", FailMode: "block"})
	cfg.VPNServers = []VPNServer{{ID: "srv", Name: "server", Type: "ocserv", Enabled: true, Subnet: "10.9.0.1/24"}}
	cfg.WiFi = []WiFiRadio{{ID: "radio", Device: "wlan0", Enabled: true, Country: "RU"}}

	result := cfg.Validate()
	var got strings.Builder
	for _, problem := range result.Problems {
		if problem.Severity == "error" {
			got.WriteString(problem.Path)
			got.WriteByte('\n')
		}
	}
	for _, want := range []string{
		"channels[1].enabled", "vpn_servers[0].enabled",
	} {
		if !strings.Contains(got.String(), want) {
			t.Errorf("нет явного запрета %s:\n%s", want, got.String())
		}
	}
}

func TestUnimplementedObjectsMayBeSavedDisabled(t *testing.T) {
	cfg := Default()
	cfg.Channels = append(cfg.Channels, Channel{ID: "xray", Index: 1, Name: "VPN", Type: "xray", Mode: "tun", FailMode: "block"})
	cfg.Policies = []Policy{{ID: "p", Name: "policy", Channel: "direct", SrcIP: "192.0.2.1"}}
	cfg.VPNServers = []VPNServer{{ID: "srv", Name: "server", Type: "wireguard", Subnet: "10.9.0.1/24"}}
	cfg.WiFi = []WiFiRadio{{ID: "radio", Device: "wlan0", Country: "RU"}}
	cfg.DNS.Blocklists = []Blocklist{{ID: "ads"}}

	for _, problem := range cfg.Validate().Problems {
		if problem.Severity == "error" && strings.Contains(problem.Message, "ещё не реализован") {
			t.Fatalf("выключенная будущая функция запрещена: %+v", problem)
		}
	}
}

func TestAdGuardHomeIsNotAdvertisedOrAcceptedBeforeImplementation(t *testing.T) {
	if _, ok := ComponentByID("adguardhome"); ok {
		t.Fatal("незавершённый AdGuard Home опубликован в каталоге компонентов")
	}
	cfg := Default()
	cfg.DNS.Enabled = true
	cfg.DNS.Provider = "adguardhome"
	for _, problem := range cfg.Validate().Problems {
		if problem.Path == "dns.provider" && problem.Severity == "error" {
			return
		}
	}
	t.Fatal("незавершённый провайдер AdGuard Home принят конфигурацией")
}

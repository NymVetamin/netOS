package api

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/eventlog"
	"github.com/netos-router/netos/internal/subsys/wifi"
)

func wifiLogConfig() *config.Config {
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "hostapd", Installed: true}}
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Name: "Home", Interface: "lan", RouterAddress: "192.168.10.1/24", Zone: "lan", Enabled: true}}
	cfg.WiFi = []config.WiFiRadio{{ID: "r", Device: "wlan0", Enabled: true, Band: "5", Channel: 36, Width: 20, Country: "RU"}}
	for i, name := range []string{"Disabled", "Main", "Skipped", "Guest", "Third"} {
		cfg.WiFi[0].SSIDs = append(cfg.WiFi[0].SSIDs, config.WiFiSSID{ID: fmt.Sprint("s", i), SSID: name, Enabled: i != 0 && i != 2, Security: "open", Network: "home"})
	}
	return cfg
}

func TestWiFiLogNamesMatchRenderedBSSAndRefresh(t *testing.T) {
	engine := apply.NewEngine(nil, true)
	s := &Server{Engine: engine, Events: eventlog.New()}
	names := s.lanNames()
	lan := &eventlog.LAN{Log: s.Events, Names: names}
	for revision := int64(1); revision <= 2; revision++ {
		cfg := wifiLogConfig()
		if revision == 2 {
			cfg.WiFi[0].SSIDs[0].Enabled = true
			cfg.WiFi[0].SSIDs[0].SSID = "Renamed"
			cfg.WiFi[0].SSIDs[1].Enabled = false
		}
		if _, err := engine.Apply(context.Background(), cfg, revision, false); err != nil {
			t.Fatal(err)
		}
		out, err := wifi.RenderRadio(cfg.WiFi[0], cfg)
		if err != nil {
			t.Fatal(err)
		}
		iface := ""
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "interface=") || strings.HasPrefix(line, "bss=") {
				iface = strings.SplitN(line, "=", 2)[1]
			}
			if !strings.HasPrefix(line, "ssid=") {
				continue
			}
			want := strings.TrimPrefix(line, "ssid=")
			if got := names.SSID(iface); got != want {
				t.Errorf("revision %d, %s: name %q, rendered %q", revision, iface, got, want)
			}
			for repeat := 0; repeat < 2; repeat++ {
				lan.WiFi(time.Now(), iface+": AP-STA-CONNECTED 02:00:00:00:00:01")
				page, _, _ := s.Events.Since(eventlog.WiFi, "", 0)
				if page.Events[0].Source != want {
					t.Errorf("event source %q, want %q", page.Events[0].Source, want)
				}
			}
		}
		for _, unknown := range []string{"wlan1", "wlan0-n0", "wlan0-n-1", "wlan0-n01", "wlan0-n+1", "wlan0-n3", "wlan0-nx"} {
			if got := names.SSID(unknown); got != "" {
				t.Errorf("unknown interface %s resolved as %q", unknown, got)
			}
		}
	}
}

func BenchmarkWiFiLogNames(b *testing.B) {
	for _, n := range []int{2, 64} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := wifiLogConfig()
			cfg.WiFi[0].SSIDs = nil
			for i := 0; i < n; i++ {
				cfg.WiFi[0].SSIDs = append(cfg.WiFi[0].SSIDs, config.WiFiSSID{ID: fmt.Sprint("s", i), SSID: fmt.Sprint("SSID", i), Enabled: true, Security: "open", Network: "home"})
			}
			e := apply.NewEngine(nil, true)
			if _, err := e.Apply(context.Background(), cfg, 1, false); err != nil {
				b.Fatal(err)
			}
			s := &Server{Engine: e, Events: eventlog.New()}
			lan := &eventlog.LAN{Log: s.Events, Names: s.lanNames()}
			line := fmt.Sprintf("wlan0-n%d: AP-STA-CONNECTED 02:00:00:00:00:01", n-1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				lan.WiFi(time.Time{}, line)
			}
		})
	}
}

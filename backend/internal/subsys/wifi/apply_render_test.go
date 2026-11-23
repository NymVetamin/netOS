package wifi

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func mustRenderRadio(t *testing.T, cfg *config.Config, radio config.WiFiRadio) []byte {
	t.Helper()
	conf, err := RenderRadio(radio, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

func TestApplyPreflightsAllRadiosAndRefreshesRenderedFiles(t *testing.T) {
	cfg := wifiConfig()
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	ctx := context.Background()
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	conf, _ := s.paths(cfg.WiFi[0])
	before, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	old := cfg.WiFi[0]
	invalid := old
	invalid.ID = "z-invalid"
	invalid.SSIDs = nil
	valid := old
	valid.ID = "a-valid"
	valid.Device = "wlan1"
	cfg.WiFi = []config.WiFiRadio{invalid, valid}
	runner.commands = nil
	if err := s.Apply(ctx, cfg); err == nil {
		t.Fatal("invalid radio accepted")
	}
	after, err := os.ReadFile(conf)
	if err != nil || !bytes.Equal(before, after) || len(runner.commands) != 0 {
		t.Fatalf("preflight changed previous radio: err=%v commands=%v", err, runner.commands)
	}
	newConf, _ := s.paths(valid)
	if _, err := os.Stat(newConf); !os.IsNotExist(err) {
		t.Fatalf("valid radio was written before invalid radio was rejected: %v", err)
	}
	valid.SSIDs = append([]config.WiFiSSID(nil), old.SSIDs...)
	valid.SSIDs[0].SSID = "Other radio"
	invalid.Enabled = false
	cfg.WiFi = []config.WiFiRadio{old, invalid, valid}
	for _, name := range []string{"Changed", "Again", "Again"} {
		cfg.WiFi[0].SSIDs[0].SSID = name
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		for _, radio := range []config.WiFiRadio{cfg.WiFi[0], cfg.WiFi[2]} {
			want := mustRenderRadio(t, cfg, radio)
			path, _ := s.paths(radio)
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("stale config for %s/%s: %v", radio.ID, name, err)
			}
		}
	}
}

func BenchmarkApplyRenderedRadios(b *testing.B) {
	for _, n := range []int{8, 256} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := wifiConfig()
			base := cfg.WiFi[0].SSIDs[0]
			cfg.WiFi[0].SSIDs = nil
			for i := 0; i < n; i++ {
				ssid := base
				ssid.ID = fmt.Sprint(i)
				cfg.WiFi[0].SSIDs = append(cfg.WiFi[0].SSIDs, ssid)
			}
			runner := &fakeRunner{}
			s := New(runner, b.TempDir())
			s.UnitDir = b.TempDir()
			ctx := context.Background()
			if err := s.Apply(ctx, cfg); err != nil {
				b.Fatal(err)
			}
			runner.commands = nil
			if err := s.Apply(ctx, cfg); err != nil {
				b.Fatal(err)
			}
			commands := len(runner.commands)
			b.ReportAllocs()
			for b.Loop() {
				runner.commands = runner.commands[:0]
				if err := s.Apply(ctx, cfg); err != nil {
					b.Fatal(err)
				}
				if len(runner.commands) != commands {
					b.Fatal("command count changed")
				}
			}
			b.ReportMetric(float64(commands), "commands/op")
		})
	}
}

package wifi

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type fakeRunner struct {
	commands []string
	active   bool
	enabled  bool
	outputs  map[string]string
	errors   map[string]error
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, cmd)
	if err := r.errors[cmd]; err != nil {
		return "", err
	}
	if output, ok := r.outputs[cmd]; ok {
		return output, nil
	}
	if strings.HasPrefix(cmd, "systemctl restart netos-hostapd-") {
		r.active = true
	}
	if strings.HasPrefix(cmd, "systemctl enable netos-hostapd-") {
		r.enabled = true
	}
	if strings.HasPrefix(cmd, "systemctl stop netos-hostapd-") {
		r.active = false
	}
	if strings.HasPrefix(cmd, "systemctl disable netos-hostapd-") {
		r.enabled = false
	}
	if strings.HasPrefix(cmd, "systemctl is-active netos-hostapd-") && r.active {
		return "active\n", nil
	}
	if strings.HasPrefix(cmd, "systemctl is-enabled netos-hostapd-") && r.enabled {
		return "enabled\n", nil
	}
	if strings.HasPrefix(cmd, "iw dev wlan0 info") && r.active {
		return "Interface wlan0\n\tssid netOS\n\ttype AP\n\tchannel 36 (5180 MHz)\n\ttxpower 18.00 dBm\n", nil
	}
	if strings.HasPrefix(cmd, "iw dev wlan0-n1 info") && r.active {
		return "Interface wlan0-n1\n\tssid netOS Guest\n\ttype AP\n\tchannel 36 (5180 MHz)\n\ttxpower 18.00 dBm\n", nil
	}
	return "", nil
}

func (r *fakeRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func wifiConfig() *config.Config {
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "hostapd", Installed: true}}
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Name: "Home", Interface: "lan", RouterAddress: "192.168.10.1/24", Zone: "lan", Enabled: true}}
	cfg.WiFi = []config.WiFiRadio{{
		ID: "radio0", Device: "wlan0", Enabled: true, Band: "5", Channel: 36, Width: 80, Country: "RU", TxPower: 18,
		SSIDs: []config.WiFiSSID{
			{ID: "main", SSID: "netOS", Enabled: true, Security: "wpa2/wpa3", Password: "correct horse", Network: "home"},
			{ID: "guest", SSID: "netOS Guest", Enabled: true, Security: "wpa3", Password: "guest-secret", Network: "home", Hidden: true, Isolate: true},
		},
	}}
	return cfg
}

func TestRenderRadio(t *testing.T) {
	out, err := RenderRadio(wifiConfig().WiFi[0], wifiConfig())
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		"interface=wlan0", "bridge=br0", "ssid=netOS", "wpa_key_mgmt=WPA-PSK SAE",
		"bss=wlan0-n1", "ssid=netOS Guest", "wpa_key_mgmt=SAE", "ap_isolate=1",
		"ht_capab=[HT40+]", "vht_oper_centr_freq_seg0_idx=42",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("render lacks %q:\n%s", want, text)
		}
	}
}

func TestFiveGHzSecondaryDirection(t *testing.T) {
	cfg := wifiConfig()
	for _, tc := range []struct {
		channel int
		want    string
	}{{36, "[HT40+]"}, {40, "[HT40-]"}, {44, "[HT40+]"}, {48, "[HT40-]"}} {
		cfg.WiFi[0].Channel = tc.channel
		out, err := RenderRadio(cfg.WiFi[0], cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), tc.want) {
			t.Errorf("channel %d lacks %s:\n%s", tc.channel, tc.want, out)
		}
	}
}

func TestApplyHealthAndCleanup(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{}
	s := New(runner, filepath.Join(root, "state"))
	s.UnitDir = filepath.Join(root, "units")
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	conf, unit := s.paths(cfg.WiFi[0])
	if info, err := os.Stat(conf); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("bad config permissions: %v, %v", info, err)
	}
	if _, err := os.Stat(unit); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatalf("config was not removed: %v", err)
	}
}

package wifi

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestRenderRadioPreservesFirstInterfaceNameAndFreshChanges(t *testing.T) {
	cfg := wifiConfig()
	radio := cfg.WiFi[0]
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: "lan", Name: "wrong"})
	check := func(name string) {
		t.Helper()
		out, err := RenderRadio(radio, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(out), "bridge="+name+"\n") != 2 || strings.Contains(string(out), "bridge=wrong\n") {
			t.Fatalf("unexpected bridges: %s", out)
		}
	}
	check("br0")
	cfg.Interfaces[0].Name = ""
	if _, err := RenderRadio(radio, cfg); err == nil || !strings.Contains(err.Error(), "не найден интерфейс") {
		t.Fatalf("empty first name bypassed: %v", err)
	}
	cfg.Interfaces[0].Name = "br-renamed"
	check("br-renamed")
	cfg.Networks = append(cfg.Networks, config.Network{ID: "home", Interface: "missing"})
	if _, err := RenderRadio(radio, cfg); err == nil {
		t.Fatal("last network reference ignored")
	}
	cfg.Networks = cfg.Networks[:1]
	check("br-renamed")
}

func TestRenderHostapdUsesCurrentSnapshotForAllRadios(t *testing.T) {
	cfg := wifiConfig()
	second := cfg.WiFi[0]
	second.Device = "wlan1"
	cfg.WiFi = append(cfg.WiFi, config.WiFiRadio{}, second)
	for _, name := range []string{"br0", "br-new"} {
		cfg.Interfaces[0].Name = name
		out, err := RenderHostapd(cfg)
		if err != nil || strings.Count(out, "bridge="+name+"\n") != 4 || strings.Index(out, "# --- wlan1 ---") <= strings.Index(out, "# --- wlan0 ---") {
			t.Fatalf("unexpected hostapd output: %q, %v", out, err)
		}
	}
	cfg.WiFi[2].SSIDs = nil
	if out, err := RenderHostapd(cfg); err == nil || out != "" {
		t.Fatalf("invalid second radio produced %q, %v", out, err)
	}
	cfg.WiFi = cfg.WiFi[1:2]
	if out, err := RenderHostapd(cfg); err != nil || !strings.HasPrefix(out, "# ") || strings.Contains(out, "interface=") {
		t.Fatalf("unexpected inactive output: %q, %v", out, err)
	}
}

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

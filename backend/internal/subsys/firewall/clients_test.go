package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestBlockedClientIsDroppedBeforeEstablishedTraffic(t *testing.T) {
	cfg := config.Default()
	cfg.Clients = []config.Client{
		{ID: "tablet", Name: "Планшет", MAC: "AA:BB:CC:DD:EE:FF", Blocked: true},
	}

	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"INPUT", "FORWARD"} {
		want := "-A " + chain + " -m mac --mac-source aa:bb:cc:dd:ee:ff"
		if !strings.Contains(rules.IPv4, want) {
			t.Errorf("нет блокировки в %s:\n%s", chain, rules.IPv4)
		}
	}
	drop := strings.Index(rules.IPv4, "--mac-source aa:bb:cc:dd:ee:ff")
	established := strings.Index(rules.IPv4, "--ctstate ESTABLISHED,RELATED")
	if drop < 0 || established < 0 || drop > established {
		t.Fatalf("блокировка стоит после разрешения established:\n%s", rules.IPv4)
	}
}

func TestBlockedClientsHaveDeterministicOrder(t *testing.T) {
	cfg := config.Default()
	cfg.Clients = []config.Client{
		{ID: "z", MAC: "ff:00:00:00:00:01", Blocked: true},
		{ID: "a", MAC: "00:00:00:00:00:01", Blocked: true},
	}
	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(rules.IPv4, "00:00:00:00:00:01") > strings.Index(rules.IPv4, "ff:00:00:00:00:01") {
		t.Fatalf("порядок зависит от порядка конфигурации:\n%s", rules.IPv4)
	}
}

package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestChannelPoliciesMarkConnectionsInPriorityOrder(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{
		ID: "wg-home", Index: 7, Name: "VPN", Enabled: true, Type: "wireguard",
	})
	cfg.Policies = []config.Policy{
		{ID: "later", Name: "HTTPS", Enabled: true, Priority: 200, Channel: "wg-home", Protocol: "tcp", DstPort: "443"},
		{ID: "first", Name: "Без VPN", Enabled: true, Priority: 100, Channel: "direct", DstIP: "192.0.2.0/24"},
	}

	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		":NETOS-POLICY - [0:0]",
		"-A PREROUTING -j CONNMARK --restore-mark",
		"-p tcp -m multiport --dports 443",
		"-j MARK --set-mark 0x1007",
		"-m mark --mark 0x1007 -j CONNMARK --save-mark",
		"-A POSTROUTING -o wg-ch7",
	} {
		if !strings.Contains(rules.IPv4, want) {
			t.Errorf("нет %q:\n%s", want, rules.IPv4)
		}
	}
	if direct, vpn := strings.Index(rules.IPv4, "Без VPN"), strings.Index(rules.IPv4, "HTTPS"); direct < 0 || vpn < 0 || direct > vpn {
		t.Fatalf("политики стоят не по приоритету:\n%s", rules.IPv4)
	}
}

func TestClientChannelOverridesNetworkDefault(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "wg-home", Index: 1, Enabled: true, Type: "wireguard"})
	cfg.Clients = []config.Client{{ID: "phone", Name: "Телефон", MAC: "AA:BB:CC:DD:EE:FF", Channel: "wg-home"}}
	cfg.Networks = []config.Network{{ID: "lan", Name: "LAN", Enabled: true, RouterAddress: "192.168.7.1/24", DefaultChannel: "wg-home"}}

	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client := strings.Index(rules.IPv4, "канал клиента")
	network := strings.Index(rules.IPv4, "канал сегмента")
	if client < 0 || network < 0 || client > network {
		t.Fatalf("настройка клиента не предшествует настройке сегмента:\n%s", rules.IPv4)
	}
}

func TestPortRangesUseIptablesSyntax(t *testing.T) {
	if got := iptablesPortSpec("53,8000-8010"); got != "53,8000:8010" {
		t.Fatal(got)
	}
}

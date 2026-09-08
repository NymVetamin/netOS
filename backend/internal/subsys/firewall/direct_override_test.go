package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestExplicitDirectOverridesInheritedVPN(t *testing.T) {
	for _, kind := range []string{"client", "wireguard", "ocserv", "ikev2"} {
		t.Run(kind, func(t *testing.T) {
			cfg := config.Default()
			cfg.Channels = append(cfg.Channels, config.Channel{ID: "exit", Index: 1, Enabled: true, Type: "wireguard"})
			child, parent := "канал VPN-пира", "канал VPN-сервера"
			if kind == "client" {
				cfg.Clients = []config.Client{{ID: "direct-device", MAC: "02:00:00:00:00:01", Channel: "direct"}, {ID: "inherit-device", MAC: "02:00:00:00:00:02"}}
				cfg.Networks = []config.Network{{ID: "lan", Enabled: true, RouterAddress: "192.0.2.1/24", DefaultChannel: "exit"}}
				child, parent = "канал клиента", "канал сегмента"
			} else {
				cfg.VPNServers = []config.VPNServer{{ID: "inbound", Index: 1, Enabled: true, Type: kind, Subnet: "10.91.0.1/24", DefaultChannel: "exit", Peers: []config.VPNPeer{
					{ID: "direct-device", Enabled: true, Address: "10.91.0.2", Channel: "direct"},
					{ID: "inherit-device", Enabled: true, Address: "10.91.0.3"},
				}}}
			}
			rules, err := Build(cfg)
			if err != nil {
				t.Fatal(err)
			}
			childAt, parentAt, matches := -1, -1, 0
			for i, line := range strings.Split(rules.IPv4, "\n") {
				if strings.Contains(line, child) {
					matches++
					childAt = i
					if !strings.HasSuffix(line, "-j RETURN") {
						t.Fatalf("explicit direct did not stop inherited routing: %s", line)
					}
				}
				if strings.Contains(line, parent) {
					parentAt = i
				}
			}
			if matches != 1 || childAt < 0 || parentAt <= childAt {
				t.Fatalf("direct override/inherit ordering: matches=%d child=%d parent=%d", matches, childAt, parentAt)
			}
		})
	}
}

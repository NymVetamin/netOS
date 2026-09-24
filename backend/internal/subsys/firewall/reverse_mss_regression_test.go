package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestReducedMTUPathClampsBothTCPHandshakeDirections(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "qa-wg", Index: 1, Name: "WG", Enabled: true, Type: "wireguard"})
	cfg.WANs = append(cfg.WANs, config.WAN{ID: "qa-ppp", Enabled: true, Proto: "pppoe"})
	set, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range []string{"wg-ch1", "ppp-qa-ppp"} {
		for _, direction := range []string{"-o", "-i"} {
			want := "-A FORWARD " + direction + " " + iface + " -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1201:65535 -j TCPMSS --set-mss 1200"
			if !strings.Contains(set.IPv4, want) {
				t.Fatalf("missing %q", want)
			}
		}
	}
}

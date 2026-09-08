package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestDNSUpstreamIsMarkedForItsChannel(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "wg-dns", Index: 7, Name: "DNS VPN", Enabled: true, Type: "wireguard"})
	cfg.DNS.Upstreams = []config.Upstream{{ID: "secure", Type: "plain", Address: "1.1.1.1", Channel: "wg-dns", Enabled: true}}
	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"-A OUTPUT -m conntrack --ctdir ORIGINAL -j CONNMARK --restore-mark",
		"-d 1.1.1.1 -p udp --dport 53",
		"-d 1.1.1.1 -p tcp --dport 53",
		"--set-mark 0x1007",
		"CONNMARK --save-mark",
	} {
		if !strings.Contains(rules.IPv4, want) {
			t.Errorf("missing %q:\n%s", want, rules.IPv4)
		}
	}
}

func TestForwardedICMPErrorsDoNotInheritChannelOutputRoute(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "vpn", Index: 1, Type: "wireguard", Enabled: true})
	cfg.DNS.Upstreams = []config.Upstream{{ID: "dns", Type: "plain", Address: "1.1.1.1", Channel: "vpn", Enabled: true}}
	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(rules.IPv4, "\n") {
		if strings.HasPrefix(line, "-A OUTPUT ") && strings.Contains(line, "CONNMARK --restore-mark") {
			original := strings.Contains(line, "--ctdir ORIGINAL")
			localReply := strings.Contains(line, "--ctdir REPLY") && strings.Contains(line, "--mark 0x80000000/0x80000000") && strings.Contains(line, "--ctmask 0x7fffffff")
			if !original && !localReply {
				t.Fatalf("forwarded ICMP error can inherit output channel: %s", line)
			}
		}
	}
}

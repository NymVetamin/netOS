package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestL2TPSourceBindingPrecedesPersonalPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{Type: "l2tp", Index: 1, Enabled: true, Peers: []config.VPNPeer{
		{Enabled: true, Address: "10.99.0.2"}, {Enabled: true, Address: "10.99.0.3"}, {Enabled: false, Address: "10.99.0.4"},
	}}, {Type: "l2tp", Index: 10, Enabled: false}}
	b := &builder{}
	b.mangle(cfg, nil)
	text := b.String()
	for _, want := range []string{
		"-A PREROUTING -i pp1-+ -j NETOS-L2TP",
		"-A NETOS-L2TP -i pp1-0a630002 -s 10.99.0.2/32 -j RETURN",
		"-A NETOS-L2TP -i pp1-0a630003 -s 10.99.0.3/32 -j RETURN",
		"-A NETOS-L2TP -j DROP",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	if strings.Contains(text, "pp10-") || strings.Contains(text, "10.99.0.4") {
		t.Fatalf("disabled binding allowed: %s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "-A PREROUTING ") {
			if line != "-A PREROUTING -i pp1-+ -j NETOS-L2TP" {
				t.Fatal("source validation must run first")
			}
			break
		}
	}
}

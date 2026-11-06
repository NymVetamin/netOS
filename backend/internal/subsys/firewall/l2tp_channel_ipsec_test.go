package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"strings"
	"testing"
)

func TestL2TPChannelGuardsSurviveFirewallReapply(t *testing.T) {
	c := config.Default()
	ch := config.Channel{ID: "l2", Type: "l2tp", Index: 7, Enabled: true, Config: map[string]any{"ipsec": true}}
	c.Channels = append(c.Channels, ch)
	for _, enabled := range []bool{true, true, false, true} {
		c.Channels[len(c.Channels)-1].Enabled = enabled
		out, err := Build(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range channels.L2TPChannelIPsecRules(ch) {
			count := strings.Count(out.IPv4, rule)
			if enabled && count != 1 || !enabled && count != 0 {
				t.Fatalf("guard count=%d enabled=%v", count, enabled)
			}
		}
	}
}

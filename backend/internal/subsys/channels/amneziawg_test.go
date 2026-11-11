package channels

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/amneziawg"
)

func TestAmneziaWGChannelRender(t *testing.T) {
	c := channelConfig()
	ch := c.Channels[1]
	ch.Type = "amneziawg"
	ch.Config["endpoint"] = "192.0.2.1:51820"
	ch.Config["amnezia"] = map[string]any{"h1": "100-200", "persistent_keepalive": "20-30"}
	text, err := RenderWireGuard(ch)
	if err != nil {
		t.Fatal(err)
	}
	state, err := amneziawg.ParseNative(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if state.Device["h1"] != "100-200" || state.Peers[0].Values["persistent_keepalive_interval"] != "20-30" {
		t.Fatal("AWG options lost")
	}
	if InterfaceName(ch) != "awg-ch1" || amneziaUnit(ch) != "netos-awg-ch1.service" {
		t.Fatal("wrong ownership")
	}
	ch.Config["amnezia"] = nil
	text, err = RenderWireGuard(ch)
	if err != nil || !strings.Contains(text, "H1 = 1\n") {
		t.Fatal("cleared options did not reset")
	}
	ch.Type = "wireguard"
	ch.Config["amnezia"] = map[string]any{"h1": "100"}
	if _, err = RenderWireGuard(ch); err == nil {
		t.Fatal("ordinary WG silently accepted AWG options")
	}
}

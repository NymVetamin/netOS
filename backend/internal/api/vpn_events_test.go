package api

import (
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/eventlog"
)

func vpnMessages(l *eventlog.Log) string {
	p, _, _ := l.Since(eventlog.VPN, "", 0)
	out := []string{}
	for i := len(p.Events) - 1; i >= 0; i-- {
		out = append(out, p.Events[i].Source+": "+p.Events[i].Message)
	}
	return strings.Join(out, "\n")
}

func TestVPNPresenceEvents(t *testing.T) {
	l := eventlog.New()
	wg := config.VPNServer{ID: "s1", Name: "Дом", Type: "wireguard", Peers: []config.VPNPeer{{ID: "p1", Name: "Телефон"}, {ID: "p2", Name: "Ноутбук"}}}
	oc := config.VPNServer{ID: "s2", Name: "Офис", Type: "ocserv", Peers: []config.VPNPeer{{ID: "u1", Name: "bob"}}}
	servers := []config.VPNServer{wg, oc}
	var p vpnPresence
	now := time.Unix(1792000000, 0)
	cycle := func(w, o []vpnClientStatus) { p.observe(l, servers, [][]vpnClientStatus{w, o}, now) }
	// Start: the phone is already connected, bob is offline.
	cycle([]vpnClientStatus{{ID: "p1", State: "recent", Endpoint: "198.51.100.1:5000"}, {ID: "p2", State: "never"}}, []vpnClientStatus{{ID: "u1", State: "offline"}})
	// Unchanged cycle, then telemetry failure (nil and "unknown") changes nothing.
	cycle([]vpnClientStatus{{ID: "p1", State: "recent"}, {ID: "p2", State: "never"}}, []vpnClientStatus{{ID: "u1", State: "offline"}})
	cycle(nil, []vpnClientStatus{{ID: "u1", State: "unknown"}})
	// bob connects, laptop handshakes, phone goes quiet.
	cycle([]vpnClientStatus{{ID: "p1", State: "idle"}, {ID: "p2", State: "recent", Endpoint: "203.0.113.9:41000"}}, []vpnClientStatus{{ID: "u1", State: "online", Endpoint: "203.0.113.5"}})
	// bob disconnects; the laptop is disabled by the administrator.
	cycle([]vpnClientStatus{{ID: "p1", State: "idle"}, {ID: "p2", State: "disabled"}}, []vpnClientStatus{{ID: "u1", State: "offline"}})
	want := strings.Join([]string{
		"Дом: Телефон подключён с 198.51.100.1:5000 (на момент запуска netOS)",
		"Дом: Телефон отключился: нет рукопожатий 3 мин (примерно)",
		"Дом: Ноутбук подключился с 203.0.113.9:41000",
		"Офис: bob подключился с 203.0.113.5",
		"Офис: bob отключился",
	}, "\n")
	if got := vpnMessages(l); got != want {
		t.Fatalf("got:\n%s", got)
	}
	// A removed server leaves no state behind.
	servers = []config.VPNServer{oc}
	p.observe(l, servers, [][]vpnClientStatus{{{ID: "u1", State: "offline"}}}, now)
	if len(p.seen) != 1 {
		t.Fatal(p.seen)
	}
}

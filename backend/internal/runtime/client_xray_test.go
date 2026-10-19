package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func resourceFixture() (*xrayResources, time.Time) {
	cfg := config.Default()
	cfg.TrafficMonitor.Enabled = true
	cfg.VPNServers = []config.VPNServer{{ID: "s", Index: 1, Type: "xray", Enabled: true, Peers: []config.VPNPeer{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}, {ID: "off"}}}}
	x := &xrayResources{}
	x.configure(cfg)
	return x, time.Unix(1700000000, 0)
}
func resourceAccess(target, user string) string {
	return "from 192.0.2.2:1234 accepted tcp:" + target + ":443 [VLESS >> direct] email: s/" + user
}

func TestXrayResourceAttribution(t *testing.T) {
	for _, status := range []string{"got answer:", "cache HIT:", "cache OPTIMISTE:"} {
		x, now := resourceFixture()
		x.consume(now, "netos-xray-srv1.service", "p1", "DOH//dns.example "+status+" www.example.com. -> [192.0.2.9, 2001:db8::9]")
		for _, user := range []string{"a", "b"} {
			x.consume(now, "netos-xray-srv1.service", "p1", resourceAccess("192.0.2.9", user))
		}
		x.consume(now, "netos-xray-srv1.service", "p1", resourceAccess("[2001:db8::9]", "a"))
		got := x.flush(now.Add(3 * time.Second))
		if len(got) != 3 || got[0].client != "vpn:s:a" || got[1].client != "vpn:s:b" {
			t.Fatalf("users: %+v", got)
		}
		for _, e := range got {
			if e.domain != "www.example.com" || e.source != "xray-dns" {
				t.Fatalf("join: %+v", e)
			}
		}
		if len(x.flush(now.Add(4*time.Second))) != 0 {
			t.Fatal("duplicate events")
		}
	}
}

func TestXrayResourceIsolationAndAmbiguity(t *testing.T) {
	for _, scenario := range []string{"ambiguous", "stale", "process", "unit", "late", "overflow"} {
		t.Run(scenario, func(t *testing.T) {
			x, now := resourceFixture()
			x.consume(now, "netos-xray-srv1.service", "p1", "DNS got answer: one.example -> [192.0.2.9]")
			process := "p1"
			at := now
			switch scenario {
			case "ambiguous":
				x.consume(now, "netos-xray-srv1.service", "p1", "DNS cache HIT: two.example -> [192.0.2.9]")
			case "stale":
				at = now.Add(11 * time.Second)
			case "process":
				process = "p2"
			case "unit":
				x.answers = map[xrayDNSKey]map[string]time.Time{{"netos-xray-srv2.service|p1", "192.0.2.9"}: {"one.example": now}}
			case "late":
				x.answers = map[xrayDNSKey]map[string]time.Time{{"netos-xray-srv1.service|p1", "192.0.2.9"}: {"one.example": now.Add(3 * time.Second)}}
			case "overflow":
				x.unsafeUntil = now.Add(time.Minute)
			}
			x.consume(at, "netos-xray-srv1.service", process, resourceAccess("192.0.2.9", "a"))
			got := x.flush(at.Add(3 * time.Second))
			if len(got) != 1 || got[0].domain != "192.0.2.9" || got[0].source != "xray-ip" {
				t.Fatalf("unsafe attribution: %+v", got)
			}
		})
	}
}

func TestXrayResourcesDirectAndDelayed(t *testing.T) {
	x, now := resourceFixture()
	got := x.consume(now, "netos-xray-srv1.service", "p1", resourceAccess("EXAMPLE.com.", "a"))
	if len(got) != 1 || got[0].domain != "example.com" || got[0].source != "xray-domain" {
		t.Fatal(got)
	}
	x.consume(now, "netos-xray-srv1.service", "p1", resourceAccess("192.0.2.9", "b"))
	if len(x.flush(now.Add(time.Second))) != 0 {
		t.Fatal("IP resolved before wait")
	}
	x.consume(now.Add(time.Second), "netos-xray-srv1.service", "p1", "DNS got answer: later.example -> [192.0.2.9]")
	got = x.flush(now.Add(3 * time.Second))
	if len(got) != 1 || got[0].domain != "later.example" {
		t.Fatal(got)
	}
	for _, user := range []string{"off", "unknown"} {
		if len(x.consume(now, "netos-xray-srv1.service", "p1", resourceAccess("example.com", user))) != 0 {
			t.Fatal("unknown user")
		}
	}
	if len(x.consume(now, "netos-xray-srv2.service", "p1", resourceAccess("example.com", "a"))) != 0 {
		t.Fatal("wrong server")
	}
	if len(x.consume(now, "netos-xray-srv1.service", "p1", "from 192.0.2.2:12 accepted udp:239.255.255.250:1900 [VLESS -> BLOCK] email: s/a")) != 0 {
		t.Fatal("blocked event")
	}
	cfg := *x.cfg
	cfg.TrafficMonitor.Enabled = false
	x.configure(&cfg)
	if len(x.consume(now, "netos-xray-srv1.service", "p1", resourceAccess("example.com", "a"))) != 0 {
		t.Fatal("disabled collection")
	}
}

func TestXrayResourcesBounds(t *testing.T) {
	x, now := resourceFixture()
	for i := 0; i < 5000; i++ {
		x.consume(now, "netos-xray-srv1.service", "p1", fmt.Sprintf("DNS got answer: d%d.example -> [192.0.2.9]", i))
	}
	if x.answerCount != 4096 || !x.limited {
		t.Fatalf("unbounded: %d", x.answerCount)
	}
	for i := 0; i < 3000; i++ {
		x.consume(now, "netos-xray-srv1.service", "p1", resourceAccess("192.0.2.9", "a"))
	}
	if len(x.pending) != 2048 {
		t.Fatal(len(x.pending))
	}
	x.flush(now.Add(time.Minute))
	if x.answerCount != 0 || len(x.answers) != 0 || len(x.pending) != 0 {
		t.Fatal("expired data retained")
	}
}

func TestXrayResourcesPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	h, err := NewClientHistory(path, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	h.enabled = true
	c := ClientCounter{ID: "vpn:s:a", Name: "Client", Address: "xray:s:a", RX: 100, TX: 100}
	if err = h.persist(now, []ClientCounter{c}); err != nil {
		t.Fatal(err)
	}
	h.addXrayResources([]xrayResource{{c.ID, "example.com", "xray-domain", now}, {c.ID, "other.example", "xray-dns", now}, {c.ID, "192.0.2.9", "xray-ip", now}})
	c.RX += 100
	if err = h.persist(now.Add(30*time.Second), []ClientCounter{c}); err != nil {
		t.Fatal(err)
	}
	h.Close()
	h, err = NewClientHistory(path, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	r, err := h.Report(context.Background(), now.Add(-time.Second), now.Add(time.Minute), []string{c.ID}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Domains) != 3 || r.Clients[0].Queries != 0 || r.Clients[0].Connections != 3 {
		t.Fatalf("mixed counts: %+v", r)
	}
	h.addXrayResources([]xrayResource{{c.ID, "disabled.example", "xray-domain", now}})
	if len(h.resources) != 0 {
		t.Fatal("disabled aggregation")
	}
	if err = h.prune(now.Add(8 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	var count int
	h.db.QueryRow("SELECT COUNT(*) FROM resources").Scan(&count)
	if count != 0 {
		t.Fatal("resources retention")
	}
}

func BenchmarkXrayResourceJoin(b *testing.B) {
	x, now := resourceFixture()
	for i := 0; i < 1000; i++ {
		x.consume(now, "netos-xray-srv1.service", "p1", fmt.Sprintf("DNS got answer: d%d.example -> [10.0.%d.%d]", i, i/250, i%250+1))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.consume(now, "netos-xray-srv1.service", "p1", resourceAccess("10.0.0.1", "a"))
		x.flush(now.Add(3 * time.Second))
	}
}

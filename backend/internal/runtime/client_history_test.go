package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestRealtimeIdentityNamePrecedence(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "lan0", Enabled: true}}
	cfg.Networks = []config.Network{{Interface: "lan", Enabled: true}}
	cfg.Clients = []config.Client{{MAC: mac}, {MAC: strings.ToUpper(mac), Name: "first"}, {MAC: mac, Name: "second"}}
	r := &clientsRunner{neighbors: `[{"dst":"192.0.2.2","lladdr":"aa:bb:cc:dd:ee:ff","dev":"lan0"},{"dst":"192.0.2.3","lladdr":"aa:bb:cc:dd:ee:03","dev":"lan0"},{"dst":"192.0.2.4","lladdr":"aa:bb:cc:dd:ee:04","dev":"wan0"}]`}
	path := filepath.Join(t.TempDir(), "leases")
	lease := fmt.Sprintf("%d %s 192.0.2.1 hostname *\n", time.Now().Add(time.Hour).Unix(), mac)
	if err := os.WriteFile(path, []byte(lease), 0600); err != nil {
		t.Fatal(err)
	}
	h := ClientHistory{Runner: r, Collector: NewCollector(r, path)}
	for _, name := range []string{"first", "renamed", "hostname"} {
		if name == "hostname" {
			cfg.Clients = nil
		} else {
			cfg.Clients[1].Name = name
		}
		got := h.RealtimeIdentities(context.Background(), cfg)
		if len(got) != 3 || got["192.0.2.1"].Name != name || got["192.0.2.2"].Name != name || got["192.0.2.2"].ID != "mac:"+mac || got["192.0.2.3"].Name != "192.0.2.3" {
			t.Fatalf("name %q: %+v", name, got)
		}
	}
}

func BenchmarkRealtimeIdentityNames(b *testing.B) {
	for _, n := range []int{32, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := config.Default()
			var leases strings.Builder
			expires := time.Now().Add(time.Hour).Unix()
			for i := 0; i < n; i++ {
				mac := fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256)
				addr := fmt.Sprintf("10.0.%d.%d", i/250, i%250+1)
				cfg.Clients = append(cfg.Clients, config.Client{MAC: mac, Name: addr})
				fmt.Fprintf(&leases, "%d %s %s host *\n", expires, mac, addr)
			}
			path := filepath.Join(b.TempDir(), "leases")
			if err := os.WriteFile(path, []byte(leases.String()), 0600); err != nil {
				b.Fatal(err)
			}
			r := &clientsRunner{neighbors: "[]"}
			h := ClientHistory{Runner: r, Collector: NewCollector(r, path)}
			b.ReportAllocs()
			for b.Loop() {
				if got := h.RealtimeIdentities(context.Background(), cfg); len(got) != n {
					b.Fatal(len(got))
				}
			}
		})
	}
}

func TestClientHistoryOwnershipAndDNS(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Now().UTC().Truncate(time.Second)
	h.enabled = true
	a := ClientCounter{ID: "mac:a", Name: "Speaker", Address: "192.0.2.2", RX: 100, TX: 200}
	h.addresses[a.Address] = a
	if err = h.persist(now, []ClientCounter{a}); err != nil {
		t.Fatal(err)
	}
	h.AddDNS(now.Add(time.Second), a.Address, "Example.COM.")
	h.AddDNS(now.Add(2*time.Second), a.Address, "example.com")
	a.RX += 300
	a.TX += 600
	if err = h.persist(now.Add(30*time.Second), []ClientCounter{a}); err != nil {
		t.Fatal(err)
	}
	// Reusing the address must not credit the first device's bytes to its new owner.
	a.ID = "mac:b"
	a.Name = "Other"
	a.RX += 1000
	a.TX += 2000
	if err = h.persist(now.Add(60*time.Second), []ClientCounter{a}); err != nil {
		t.Fatal(err)
	}
	a.RX += 50
	a.TX += 70
	if err = h.persist(now.Add(90*time.Second), []ClientCounter{a}); err != nil {
		t.Fatal(err)
	}
	r, err := h.Report(context.Background(), now.Add(-time.Second), now.Add(100*time.Second), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Clients) != 2 || r.Clients[0].TX != 600 || r.Clients[1].TX != 70 {
		t.Fatalf("attribution: %+v", r.Clients)
	}
	if len(r.Domains) != 1 || r.Domains[0].Count != 2 || r.Domains[0].Domain != "example.com" || r.Domains[0].Client != "mac:a" {
		t.Fatalf("DNS: %+v", r.Domains)
	}
	h.enabled = false
	h.AddDNS(now, a.Address, "disabled.example")
	if len(h.dns) != 0 {
		t.Fatal("disabled collection recorded DNS")
	}
}
func TestClientCounterResetDoesNotSpike(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Now()
	a := ClientCounter{ID: "a", Address: "192.0.2.3", TX: 10000}
	_ = h.persist(now, []ClientCounter{a})
	a.TX = 10
	_ = h.persist(now.Add(30*time.Second), []ClientCounter{a})
	a.TX = 100
	_ = h.persist(now.Add(time.Minute), []ClientCounter{a})
	r, err := h.Report(context.Background(), now.Add(-time.Second), now.Add(2*time.Minute), nil, false)
	if err != nil || len(r.Clients) != 1 || r.Clients[0].TX != 90 {
		t.Fatalf("reset: %+v %v", r, err)
	}
}
func TestDNSProviderQueryParsing(t *testing.T) {
	for _, line := range []string{"dnsmasq[2]: query[A] example.com from 192.0.2.2", "[1:0] info: 192.0.2.2 example.com. A IN"} {
		addr, domain := ParseDNSQuery(line)
		if addr != "192.0.2.2" || domain == "" {
			t.Fatalf("%q %q", addr, domain)
		}
	}
	if a, _ := ParseDNSQuery("dnsmasq[2]: reply example.com is 192.0.2.3"); a != "" {
		t.Fatal("reply counted as query")
	}
}
func TestNftClientCounters(t *testing.T) {
	raw := `{"nftables":[{"set":{"name":"up4","elem":[{"elem":{"val":"192.0.2.2","counter":{"packets":2,"bytes":123}}}]}},{"set":{"name":"down4","elem":[{"elem":{"val":"192.0.2.2","counter":{"bytes":456}}}]}}]}`
	c, err := ParseClientCounters(raw)
	if err != nil || c["192.0.2.2"].RX != 456 || c["192.0.2.2"].TX != 123 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestClientHistoryRetentionWhileDisabled(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Now()
	_, err = h.db.Exec("INSERT INTO traffic VALUES(?,?,?,?,?,?,?)", now.Add(-8*24*time.Hour).Unix(), "a", "a", "192.0.2.2", 1, 2, 30)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.prune(now); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = h.db.QueryRow("SELECT count(*) FROM traffic").Scan(&n); err != nil || n != 0 {
		t.Fatalf("retention: %d %v", n, err)
	}
}
func TestClientHistoryMultipleAddresses(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Now().Truncate(time.Minute)
	values := []ClientCounter{{ID: "a", Name: "client", Address: "192.0.2.2"}, {ID: "a", Name: "client", Address: "2001:db8::2"}}
	if err = h.persist(now, values); err != nil {
		t.Fatal(err)
	}
	values[0].RX = 300
	values[1].RX = 600
	if err = h.persist(now.Add(30*time.Second), values); err != nil {
		t.Fatal(err)
	}
	r, err := h.Report(context.Background(), now, now.Add(time.Minute), nil, false)
	if err != nil || len(r.Points) != 1 || r.Points[0].RX != 240 || r.Clients[0].RX != 900 {
		t.Fatalf("multi-address rates: %+v %v", r, err)
	}
}

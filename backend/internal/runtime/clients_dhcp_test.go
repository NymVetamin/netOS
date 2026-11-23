package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientsKeepInterfaceOfLeasedAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.leases")
	writeLease := func(ip string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("1999999999 aa:bb:cc:dd:ee:01 "+ip+" phone *\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeLease("10.1.0.7")
	runner := &clientsRunner{}
	c := NewCollector(runner, path)
	local := map[string]bool{"lan1": true, "lan2": true}
	matching := "10.1.0.7 dev lan1 lladdr aa:bb:cc:dd:ee:01 STALE\n"
	other := "10.2.0.8 dev lan2 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
	for _, tc := range []struct {
		name, neighbors, iface, source string
		online                         bool
	}{
		{"matching-first", matching + other, "lan1", "both", true},
		{"matching-last", other + matching, "lan1", "both", true},
		{"other-only", other, "", "both", true},
		{"matching-only", matching, "lan1", "both", false},
		{"no-neighbors", "", "", "dhcp", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner.neighbors = tc.neighbors
			for range 2 {
				got, err := c.Clients(context.Background(), local)
				if err != nil || len(got) != 1 {
					t.Fatalf("clients=%+v err=%v", got, err)
				}
				cl := got[0]
				if cl.IP != "10.1.0.7" || cl.Interface != tc.iface || cl.Source != tc.source || cl.Online != tc.online || cl.Hostname != "phone" || cl.Expires == nil {
					t.Fatalf("unexpected client: %+v", cl)
				}
			}
		})
	}
	runner.neighbors = other + matching
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 70*1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Clients(context.Background(), local); err == nil {
		t.Fatal("expected lease scanner error")
	}
	writeLease("10.2.0.8")
	got, err := c.Clients(context.Background(), local)
	if err != nil || len(got) != 1 || got[0].IP != "10.2.0.8" || got[0].Interface != "lan2" {
		t.Fatalf("fresh lease: %+v err=%v", got, err)
	}
}

func BenchmarkClientsDHCP(b *testing.B) {
	for _, n := range []int{16, 4096} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var leases, neighbors strings.Builder
			for i := 0; i < n; i++ {
				mac := fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256)
				ip := fmt.Sprintf("10.1.%d.%d", i/256, i%256)
				fmt.Fprintf(&leases, "1999999999 %s %s phone *\n", mac, ip)
				fmt.Fprintf(&neighbors, "%s dev lan1 lladdr %s STALE\n10.2.%d.%d dev lan2 lladdr %s REACHABLE\n", ip, mac, i/256, i%256, mac)
			}
			path := filepath.Join(b.TempDir(), "dnsmasq.leases")
			if err := os.WriteFile(path, []byte(leases.String()), 0o600); err != nil {
				b.Fatal(err)
			}
			c := NewCollector(&clientsRunner{neighbors: neighbors.String()}, path)
			local := map[string]bool{"lan1": true, "lan2": true}
			b.ReportAllocs()
			for b.Loop() {
				got, err := c.Clients(context.Background(), local)
				if err != nil || len(got) != n {
					b.Fatalf("count=%d err=%v", len(got), err)
				}
			}
		})
	}
}

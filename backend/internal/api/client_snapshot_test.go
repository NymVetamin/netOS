package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	rt "github.com/netos-router/netos/internal/runtime"
)

func clientSnapshotServer(t testing.TB, n int) (*Server, *int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leases")
	var data strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&data, "4102444800 02:00:%02x:%02x:%02x:01 192.168.50.%d client%d *\n", i>>16, (i>>8)&255, i&255, i%250+1, i)
	}
	// Preserve the original duplicate lease records, not just the client aggregate.
	data.WriteString("4102444801 02:00:00:00:00:01 192.168.50.251 newer *\n")
	if err := os.WriteFile(path, []byte(data.String()), 0600); err != nil {
		t.Fatal(err)
	}
	engine := apply.NewEngine(nil, true)
	if _, err := engine.Apply(context.Background(), config.Default(), 1, false); err != nil {
		t.Fatal(err)
	}
	reads := new(int)
	collector := rt.NewCollector(&observationRunner{}, path)
	collector.LeaseProvider = func() string { *reads++; return "dnsmasq" }
	return &Server{Engine: engine, Collector: collector}, reads
}

func snapshotJSON(t testing.TB, s *Server, path string) map[string]json.RawMessage {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", path, nil)
	if path == "/api/leases" {
		s.handleLeases(w, r)
	} else {
		s.handleClients(w, r)
	}
	if w.Code != 200 {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestClientSnapshotSharesLeaseRead(t *testing.T) {
	s, reads := clientSnapshotServer(t, 16)
	clients := snapshotJSON(t, s, "/api/clients")
	leases := snapshotJSON(t, s, "/api/leases")
	if *reads != 2 {
		t.Fatal(*reads)
	}
	if _, ok := clients["leases"]; ok {
		t.Fatal("legacy response changed")
	}
	*reads = 0
	for repeat := 0; repeat < 2; repeat++ {
		got := snapshotJSON(t, s, "/api/clients?leases=1")
		if !reflect.DeepEqual(got["clients"], clients["clients"]) || !reflect.DeepEqual(got["leases"], leases["leases"]) {
			t.Fatal("combined response differs")
		}
	}
	if *reads != 2 {
		t.Fatalf("reads=%d want2", *reads)
	}
	if err := os.WriteFile(s.Collector.LeasePath, []byte("4102444800 02:11:22:33:44:55 192.168.50.25 fresh *\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := snapshotJSON(t, s, "/api/clients?leases=1")
	if !strings.Contains(string(got["clients"]), "fresh") || !strings.Contains(string(got["leases"]), "fresh") {
		t.Fatal("stale response")
	}
	if err := os.Remove(s.Collector.LeasePath); err != nil {
		t.Fatal(err)
	}
	empty := snapshotJSON(t, s, "/api/clients?leases=1")
	if string(empty["leases"]) != "null" {
		t.Fatalf("empty=%s", empty["leases"])
	}
	// A directory cannot be parsed as a lease file on either Windows or Linux.
	if err := os.Mkdir(s.Collector.LeasePath, 0700); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		w := httptest.NewRecorder()
		s.handleClients(w, httptest.NewRequest("GET", "/api/clients?leases=1", nil))
		if w.Code != 500 {
			t.Fatalf("lease error=%d", w.Code)
		}
	}
	if err := os.Remove(s.Collector.LeasePath); err != nil {
		t.Fatal(err)
	}
	snapshotJSON(t, s, "/api/clients?leases=1")
}

func BenchmarkClientPollSnapshot(b *testing.B) {
	for _, n := range []int{16, 2048} {
		for _, combined := range []bool{false, true} {
			b.Run(fmt.Sprintf("leases%d/combined%t", n, combined), func(b *testing.B) {
				s, reads := clientSnapshotServer(b, n)
				b.ReportAllocs()
				for b.Loop() {
					*reads = 0
					if combined {
						snapshotJSON(b, s, "/api/clients?leases=1")
					} else {
						snapshotJSON(b, s, "/api/clients")
						snapshotJSON(b, s, "/api/leases")
					}
					want := 2
					if combined {
						want = 1
					}
					if *reads != want {
						b.Fatal(*reads)
					}
				}
			})
		}
	}
}

type snapshotARPFailure struct{ observationRunner }

func (r *snapshotARPFailure) Run(context.Context, string, ...string) (string, error) {
	return "", fmt.Errorf("ARP unavailable")
}
func TestClientSnapshotARPFailure(t *testing.T) {
	s, reads := clientSnapshotServer(t, 1)
	s.Collector.Runner = &snapshotARPFailure{}
	for range 2 {
		w := httptest.NewRecorder()
		s.handleClients(w, httptest.NewRequest("GET", "/api/clients?leases=1", nil))
		if w.Code != 500 || !strings.Contains(w.Body.String(), "ARP unavailable") {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	}
	if *reads != 2 {
		t.Fatal(*reads)
	}
	s.Collector.Runner = &observationRunner{}
	snapshotJSON(t, s, "/api/clients?leases=1")
}

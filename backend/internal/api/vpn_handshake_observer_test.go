package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func handshakeSamples(n int) []vpnHandshakeSample {
	s := vpnHandshakeSample{server: config.VPNServer{ID: "server", Index: 4, Name: "Server", Enabled: true, Type: "wireguard"}}
	for i := 0; i < n; i++ {
		id := fmt.Sprint(i)
		s.server.Peers = append(s.server.Peers, config.VPNPeer{ID: id, Name: "Peer " + id, Enabled: true, Credentials: map[string]string{"public_key": "public" + id, "private_key": "SECRET", "preshared_key": "SECRET"}})
		s.rows = append(s.rows, vpnClientStatus{ID: id, PublicKey: "public" + id, State: "recent", TrafficKnown: true, LastHandshake: 100, Endpoint: "192.0.2.1:51820"})
	}
	return []vpnHandshakeSample{s}
}

func TestHandshakeObservationTruthAndFreshness(t *testing.T) {
	now := time.Unix(110, 0)
	samples := handshakeSamples(1)
	var observer vpnHandshakeObserver
	first := observer.observe(samples, now)
	if len(first) != 1 || !first[0].Initial || first[0].Handshake != 100 || first[0].Observed != 110 {
		t.Fatal(first)
	}
	encoded, _ := json.Marshal(first)
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "public0") {
		t.Fatal("credential in event", string(encoded))
	}
	samples[0].server.Name = "Renamed"
	samples[0].server.Peers[0].Name = "Renamed peer"
	if got := observer.observe(samples, now); len(got) != 0 {
		t.Fatal("rename repeated handshake", got)
	}
	samples[0].rows[0].State = "unknown"
	samples[0].rows[0].LastHandshake = 0
	if got := observer.observe(samples, now); len(got) != 0 {
		t.Fatal("failure fabricated event", got)
	}
	samples[0].rows[0].State = "idle"
	samples[0].rows[0].LastHandshake = 100
	if got := observer.observe(samples, now); len(got) != 0 {
		t.Fatal("retry repeated handshake", got)
	}
	samples[0].rows[0].LastHandshake = 105
	if got := observer.observe(samples, now); len(got) != 1 || got[0].Initial || got[0].ServerName != "Renamed" || got[0].PeerName != "Renamed peer" {
		t.Fatal(got)
	}
	samples[0].rows[0].LastHandshake = 111
	if got := observer.observe(samples, now); len(got) != 0 {
		t.Fatal("future handshake", got)
	}
	observer.observe(nil, now)
	if len(observer.seen) != 0 {
		t.Fatal("removed peers retained")
	}
}

func TestHandshakeObservationKindsAndBounds(t *testing.T) {
	now := time.Unix(110, 0)
	var observer vpnHandshakeObserver
	samples := handshakeSamples(3000)
	samples[0].server.Config = map[string]any{"amneziawg": map[string]any{}}
	got := observer.observe(samples, now)
	if len(got) != 65 || got[0].Protocol != "amneziawg" || got[64].Suppressed != 2936 || len(observer.seen) != 3000 {
		t.Fatal(len(got), got[len(got)-1])
	}
	if repeat := observer.observe(samples, now); len(repeat) != 0 {
		t.Fatal("suppressed events retried", len(repeat))
	}
	samples[0].server.Peers = samples[0].server.Peers[:1]
	samples[0].server.Peers[0].Enabled = false
	if got := observer.observe(samples, now); len(got) != 0 || len(observer.seen) != 0 {
		t.Fatal("disabled peer retained")
	}
}

func TestHandshakeFirstReliableSnapshotAfterFailure(t *testing.T) {
	samples := handshakeSamples(1)
	var observer vpnHandshakeObserver
	now := time.Unix(110, 0)
	samples[0].rows[0].State = "unknown"
	observer.observe(samples, now)
	samples[0].rows[0].State = "recent"
	got := observer.observe(samples, now)
	if len(got) != 1 || !got[0].Initial {
		t.Fatal("failure mistaken for authoritative initial snapshot", got)
	}
}

func TestHandshakeIdentityReplacementAndCycleWideLimit(t *testing.T) {
	var observer vpnHandshakeObserver
	now := time.Unix(110, 0)
	samples := handshakeSamples(1)
	observer.observe(samples, now)
	samples[0].server.Peers[0].Credentials["public_key"] = "replacement"
	if got := observer.observe(samples, now); len(got) != 0 {
		t.Fatal("old key row attributed to replacement", got)
	}
	samples[0].rows[0].PublicKey = "replacement"
	if got := observer.observe(samples, now); len(got) != 1 || !got[0].Initial {
		t.Fatal("new identity lost", got)
	}
	a, b := handshakeSamples(70)[0], handshakeSamples(70)[0]
	b.server.ID = "second"
	observer = vpnHandshakeObserver{}
	got := observer.observe([]vpnHandshakeSample{a, b}, now)
	if len(got) != 65 || got[64].Suppressed != 76 {
		t.Fatal("limit multiplied by server count", len(got))
	}
}

func BenchmarkHandshakeObservation(b *testing.B) {
	for _, n := range []int{30, 3000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			samples := handshakeSamples(n)
			var observer vpnHandshakeObserver
			now := time.Unix(110, 0)
			observer.observe(samples, now)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				observer.observe(samples, now)
			}
		})
	}
}

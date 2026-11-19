package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	rt "github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/system"
)

func TestRealtimeWaitsForNextSharedSnapshot(t *testing.T) {
	s := &Server{}
	s.realtime.running = true
	s.realtime.changed = make(chan struct{})
	s.realtime.snapshot.Sequence = 7
	request := httptest.NewRequest("GET", "/api/statistics/realtime?after=7", nil)
	request = request.WithContext(context.WithValue(request.Context(), ctxRole, "admin"))
	done := make(chan struct{})
	w := httptest.NewRecorder()
	go func() { s.handleRealtime(w, request); close(done) }()
	select {
	case <-done:
		t.Fatal("returned duplicate without waiting")
	case <-time.After(20 * time.Millisecond):
	}
	s.realtime.mu.Lock()
	s.realtime.snapshot.Sequence = 8
	close(s.realtime.changed)
	s.realtime.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("missed notification")
	}
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestRealtimeRateResetGapAndAddressChange(t *testing.T) {
	at := time.Now()
	values := []rt.ClientCounter{{ID: "a", Address: "ip1", RX: 100, SampledAt: at}}
	rows, prev := realtimeRates(values, nil)
	if rows[0].RXBPS != nil {
		t.Fatal("invented baseline")
	}
	values[0].RX = 1100
	values[0].SampledAt = at.Add(time.Second)
	rows, prev = realtimeRates(values, prev)
	if *rows[0].RXBPS != 8000 {
		t.Fatal(rows)
	}
	values = append(values, rt.ClientCounter{ID: "a", Address: "ip2", RX: 999999, SampledAt: at.Add(2 * time.Second)})
	values[0].RX = 2100
	values[0].SampledAt = at.Add(2 * time.Second)
	rows, prev = realtimeRates(values, prev)
	if rows[0].RXBPS != nil {
		t.Fatal("new address spike")
	}
	values[0].RX = 0
	values[0].SampledAt = at.Add(3 * time.Second)
	values = values[:1]
	rows, prev = realtimeRates(values, prev)
	if rows[0].RXBPS != nil {
		t.Fatal("reset spike")
	}
	values[0].RX = 100
	values[0].SampledAt = at.Add(10 * time.Second)
	rows, _ = realtimeRates(values, prev)
	if rows[0].RXBPS != nil {
		t.Fatal("gap filled")
	}
}

func realtimeScopeConfig(prefix string) *config.Config {
	cfg := config.Default()
	cfg.TrafficMonitor.Enabled = true
	cfg.Interfaces = []config.Interface{{ID: "p", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Name: "LAN", Zone: "lan", Enabled: true, Interface: "p", RouterAddress: prefix}}
	return cfg
}

func TestRealtimeCountersFollowCurrentSubnet(t *testing.T) {
	runner := &sessionRunner{out: `{"nftables":[{"set":{"name":"up4","elem":[{"elem":{"val":"192.0.2.10","counter":{"bytes":100}}},{"elem":{"val":"203.0.113.9","counter":{"bytes":123}}}]}}]}`}
	checkRealtimeSubnets(t, runner)
}

func checkRealtimeSubnets(t *testing.T, runner system.Runner) {
	t.Helper()
	ctx := context.Background()
	leases := filepath.Join(t.TempDir(), "leases")
	if err := os.WriteFile(leases, []byte(fmt.Sprintf("%d 02:00:00:00:00:10 192.0.2.10 laptop *\n", time.Now().Add(time.Hour).Unix())), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Engine: apply.NewEngine(nil, true), ClientHistory: &rt.ClientHistory{Runner: runner, Collector: rt.NewCollector(runner, leases)}}
	for i, tc := range []struct {
		prefix, id string
		bytes      uint64
	}{
		{"192.0.2.1/24", "mac:02:00:00:00:00:10", 100}, {"203.0.113.1/24", "ip:203.0.113.9", 123}, {"192.0.2.1/24", "mac:02:00:00:00:00:10", 100},
	} {
		if _, err := s.Engine.Apply(ctx, realtimeScopeConfig(tc.prefix), int64(i+1), false); err != nil {
			t.Fatal(err)
		}
		for sample := 0; sample < 2; sample++ {
			if sample == 1 {
				// Model the one-second sampling interval without relying on timer resolution.
				for key, prev := range s.realtime.previous {
					prev.SampledAt = prev.SampledAt.Add(-time.Second)
					s.realtime.previous[key] = prev
				}
			}
			snap := s.collectRealtime(ctx)
			found := 0
			for _, v := range snap.Values {
				if strings.HasPrefix(v.ID, "if:") {
					continue
				}
				if v.ID != tc.id || v.TX != tc.bytes || (v.TXBPS == nil) != (sample == 0) {
					t.Fatalf("subnet %s sample %d: %+v", tc.prefix, sample, v)
				}
				found++
			}
			if found != 1 {
				t.Fatalf("subnet %s: %v", tc.prefix, snap)
			}
		}
	}
}

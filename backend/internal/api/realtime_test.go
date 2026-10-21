package api

import (
	"context"
	rt "github.com/netos-router/netos/internal/runtime"
	"net/http/httptest"
	"testing"
	"time"
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

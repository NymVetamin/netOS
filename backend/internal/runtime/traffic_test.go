package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	stdruntime "runtime"
	"testing"
	"time"
)

func TestTrafficHistoryRatesResetAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	samples := [][]InterfaceStat{
		{{Name: "eth0", RXBytes: 1000, TXBytes: 2000}},
		{{Name: "eth0", RXBytes: 4000, TXBytes: 8000}},
		{{Name: "eth0", RXBytes: 10, TXBytes: 20}},
	}
	h := &TrafficHistory{Path: path, Interval: 30 * time.Second, Retain: time.Hour, Now: func() time.Time { return now }}
	h.Collect = func() ([]InterfaceStat, error) {
		result := samples[0]
		samples = samples[1:]
		return result, nil
	}
	h.sample()
	now = now.Add(30 * time.Second)
	h.sample()
	points := h.Points(time.Time{}, []string{"eth0"})
	if got := points[1].Interfaces["eth0"]; got.RXBPS != 800 || got.TXBPS != 1600 {
		t.Fatalf("wrong rates: %+v", got)
	}
	now = now.Add(30 * time.Second)
	h.sample()
	if got := h.Points(time.Time{}, nil)[2].Interfaces["eth0"]; got.RXBPS != 0 || got.TXBPS != 0 {
		t.Fatalf("counter reset produced a spike: %+v", got)
	}
	if info, err := os.Stat(path); err != nil || (stdruntime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("history file mode: %v %v", info, err)
	}
	loaded := &TrafficHistory{Path: path, Retain: time.Hour, Now: func() time.Time { return now }}
	if err := loaded.load(); err != nil {
		t.Fatal(err)
	}
	if len(loaded.Points(time.Time{}, nil)) != 3 {
		t.Fatal("persisted points were not loaded")
	}
}

func TestTrafficHistoryConstructorRunAndCollectionFailure(t *testing.T) {
	collector := NewCollector(&observationRunner{}, "")
	h := NewTrafficHistory(filepath.Join(t.TempDir(), "traffic.jsonl"), collector)
	if h.Interval != 30*time.Second || h.Retain != 7*24*time.Hour || h.Collect == nil || h.Now == nil {
		t.Fatalf("defaults=%+v", h)
	}

	h.Interval = 5 * time.Millisecond
	collected := make(chan struct{}, 1)
	h.Collect = func() ([]InterfaceStat, error) {
		select {
		case collected <- struct{}{}:
		default:
		}
		return []InterfaceStat{{Name: "eth0", RXBytes: 1, TXBytes: 2}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.Run(ctx)
		close(done)
	}()
	select {
	case <-collected:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("traffic run did not collect")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("traffic run ignored cancellation")
	}
	if len(h.Points(time.Time{}, nil)) == 0 {
		t.Fatal("traffic run did not retain its sample")
	}

	before := len(h.Points(time.Time{}, nil))
	h.Collect = func() ([]InterfaceStat, error) { return nil, errors.New("stats failed") }
	h.sample()
	if after := len(h.Points(time.Time{}, nil)); after != before {
		t.Fatalf("failed collection appended a point: before=%d after=%d", before, after)
	}
}

func TestTrafficHistoryMigratesLegacyArrayWithoutRewritingEverySample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	legacy, _ := json.Marshal([]TrafficPoint{{At: now.Add(-time.Minute), Interfaces: map[string]TrafficRate{"eth0": {RXBytes: 1}}}})
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	h := &TrafficHistory{Path: path, Retain: time.Hour, Now: func() time.Time { return now }, Collect: func() ([]InterfaceStat, error) {
		return []InterfaceStat{{Name: "eth0", RXBytes: 2}}, nil
	}}
	if err := h.load(); err != nil {
		t.Fatal(err)
	}
	h.sample()
	loaded := &TrafficHistory{Path: path, Retain: time.Hour, Now: func() time.Time { return now }}
	if err := loaded.load(); err != nil {
		t.Fatal(err)
	}
	if got := len(loaded.Points(time.Time{}, nil)); got != 2 {
		t.Fatalf("точек после миграции %d, ожидалось 2", got)
	}
}

func TestTrafficHistoryPrunesOldPoints(t *testing.T) {
	now := time.Now().UTC()
	h := &TrafficHistory{Retain: time.Hour, points: []TrafficPoint{{At: now.Add(-2 * time.Hour)}, {At: now.Add(-30 * time.Minute)}}}
	h.pruneLocked(now.Add(-time.Hour))
	if len(h.points) != 1 || !h.points[0].At.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("old points were not pruned: %+v", h.points)
	}
}

func TestTrafficWindowBoundsMissingInterfacesAndIndependentOutput(t *testing.T) {
	now := time.Unix(1800000000, 0)
	h := &TrafficHistory{Interval: 30 * time.Second}
	for i := 0; i <= 4; i++ {
		p := TrafficPoint{At: now.Add(time.Duration(i) * 30 * time.Second), Interfaces: map[string]TrafficRate{
			"lan": {RXBPS: 999},
		}}
		if i != 1 {
			p.Interfaces["wan"] = TrafficRate{RXBytes: int64(i * 100), TXBytes: int64(i * 200), RXBPS: int64(i*20 + 10), TXBPS: int64(i*40 + 20)}
		}
		h.points = append(h.points, p)
	}
	before := h.Points(time.Time{}, nil)
	out := h.Window(now, now.Add(120*time.Second), []string{"", "wan", "wan"}, 2)
	want := []TrafficPoint{
		{At: now, Interfaces: map[string]TrafficRate{"wan": {RXBPS: 5, TXBPS: 10}}},
		{At: now.Add(60 * time.Second), Interfaces: map[string]TrafficRate{"wan": {RXBytes: 300, TXBytes: 600, RXBPS: 60, TXBPS: 120}}},
		{At: now.Add(120 * time.Second), Interfaces: map[string]TrafficRate{"wan": {RXBytes: 400, TXBytes: 800, RXBPS: 90, TXBPS: 180}}},
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("bucket/filter/end semantics: %+v", out)
	}
	out[0].Interfaces["wan"] = TrafficRate{RXBPS: 123456}
	if !reflect.DeepEqual(before, h.Points(time.Time{}, nil)) {
		t.Fatal("output map aliases stored samples")
	}
	shifted := h.Window(now.Add(15*time.Second), now.Add(105*time.Second), []string{"wan"}, 2)
	if len(shifted) != 2 || len(shifted[0].Interfaces) != 0 || !shifted[0].At.Equal(now.Add(30*time.Second)) || shifted[1].Interfaces["wan"].RXBPS != 60 {
		t.Fatalf("shifted/missing: %+v", shifted)
	}
	if !reflect.DeepEqual(h.Window(now, now.Add(120*time.Second), nil, 0), h.Window(now, now.Add(120*time.Second), []string{""}, 2)) {
		t.Fatal("minimum limit/empty filter changed")
	}
	if len(h.Window(now.Add(time.Hour), now.Add(2*time.Hour), nil, 600)) != 0 {
		t.Fatal("empty range returned samples")
	}
}

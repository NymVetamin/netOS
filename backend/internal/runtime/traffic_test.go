package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	stdruntime "runtime"
	"testing"
	"time"
)

func TestTrafficRestartAfterInterruptedAppend(t *testing.T) {
	for _, tail := range []string{"partial", "missing newline"} {
		t.Run(tail, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			path := filepath.Join(t.TempDir(), "history")
			var data bytes.Buffer
			var want []TrafficPoint
			for i := 0; i < 100; i++ {
				point := TrafficPoint{At: now.Add(time.Duration(i-100) * time.Second), Interfaces: map[string]TrafficRate{"lan": {RXBytes: int64(i)}}}
				if err := json.NewEncoder(&data).Encode(point); err != nil {
					t.Fatal(err)
				}
				want = append(want, point)
			}
			if tail == "partial" {
				data.WriteString(`{"at":`)
			} else {
				data.Truncate(data.Len() - 1)
			}
			if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			for i := 0; i < 2; i++ {
				h := NewTrafficHistory(path, &Collector{})
				h.Now = func() time.Time { return now }
				h.Collect = func() ([]InterfaceStat, error) {
					return []InterfaceStat{{Name: "lan", RXBytes: int64(100 + i)}}, nil
				}
				h.Run(ctx)
				want = append(want, TrafficPoint{At: now, Interfaces: map[string]TrafficRate{"lan": {RXBytes: int64(100 + i), RXBPS: 8}}})
				if got := h.Points(time.Time{}, nil); !reflect.DeepEqual(got, want) {
					t.Fatalf("restart %d: got %d points, expected %d with original counters and rates", i, len(got), len(want))
				}
				now = now.Add(time.Second)
			}
		})
	}
}

func BenchmarkTrafficRestart(b *testing.B) {
	for _, n := range []int{100, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			now := time.Now().UTC()
			var data bytes.Buffer
			enc := json.NewEncoder(&data)
			for i := 0; i < n; i++ {
				if err := enc.Encode(TrafficPoint{At: now.Add(time.Duration(i-n) * time.Second), Interfaces: map[string]TrafficRate{"lan": {RXBytes: int64(i)}}}); err != nil {
					b.Fatal(err)
				}
			}
			path := filepath.Join(b.TempDir(), "history")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			b.ReportAllocs()
			for b.Loop() {
				b.StopTimer()
				if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				h := NewTrafficHistory(path, &Collector{})
				h.Now = func() time.Time { return now }
				h.Collect = func() ([]InterfaceStat, error) { return nil, nil }
				h.Run(ctx)
				if len(h.points) != n+1 {
					b.Fatal(len(h.points))
				}
			}
		})
	}
}

func TestTrafficRestartReadsLargeJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	now := time.Now().UTC()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	point := TrafficPoint{At: now, Interfaces: map[string]TrafficRate{"lan": {RXBytes: 12}}}
	record, err := json.Marshal(point)
	if err != nil {
		t.Fatal(err)
	}
	line := append(append(record, bytes.Repeat([]byte(" "), 1<<20)...), '\n')
	for i := 0; i < 65; i++ {
		if _, err := file.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		h := NewTrafficHistory(path, &Collector{})
		h.Now = func() time.Time { return now }
		h.Collect = func() ([]InterfaceStat, error) { return nil, nil }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h.Run(ctx)
		if len(h.points) != 66+attempt || !reflect.DeepEqual(h.points[0], point) {
			t.Fatalf("restart %d: retained %d points", attempt, len(h.points))
		}
	}
}

func TestTrafficLoadFailurePreservesJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	original := []byte("invalid complete record\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	h := NewTrafficHistory(path, &Collector{})
	h.Collect = func() ([]InterfaceStat, error) { return nil, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.Run(ctx)
	h.sample()
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) || len(h.points) != 2 {
		t.Fatalf("after failed load: data=%q samples=%d err=%v", data, len(h.points), err)
	}
}

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

func TestTrafficClockRollback(t *testing.T) {
	base := time.Unix(1800000000, 0).UTC()
	now := base
	var counter int64
	h := NewTrafficHistory(filepath.Join(t.TempDir(), "history"), &Collector{})
	h.Now = func() time.Time { return now }
	h.Collect = func() ([]InterfaceStat, error) {
		counter += 30
		return []InterfaceStat{{Name: "lan", RXBytes: counter}}, nil
	}
	for _, seconds := range []int{300, 0, 0, 30} {
		now = base.Add(time.Duration(seconds) * time.Second)
		h.sample()
	}
	checkWindow := func() {
		t.Helper()
		got := h.Window(base, base.Add(time.Minute), nil, 60)
		if len(got) != 2 || got[0].Interfaces["lan"].RXBytes != 90 || got[1].Interfaces["lan"].RXBPS != 8 {
			t.Fatalf("clock rollback window: %+v", got)
		}
	}
	checkWindow()
	for attempt := 0; attempt < 2; attempt++ {
		restarted := NewTrafficHistory(h.Path, &Collector{})
		restarted.Now, restarted.Collect = h.Now, h.Collect
		h = restarted
		if err := h.load(); err != nil {
			t.Fatal(err)
		}
		checkWindow()
		now = now.Add(90 * time.Second)
		h.sample()
		got := h.Window(now, now, nil, 2)
		if len(got) != 1 || got[0].Interfaces["lan"].RXBPS != 2 {
			t.Fatalf("first rate after restart: %+v", got)
		}
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

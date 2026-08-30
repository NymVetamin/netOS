package runtime

import (
	"os"
	"path/filepath"
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

func TestTrafficHistoryPrunesOldPoints(t *testing.T) {
	now := time.Now().UTC()
	h := &TrafficHistory{Retain: time.Hour, points: []TrafficPoint{{At: now.Add(-2 * time.Hour)}, {At: now.Add(-30 * time.Minute)}}}
	h.pruneLocked(now.Add(-time.Hour))
	if len(h.points) != 1 || !h.points[0].At.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("old points were not pruned: %+v", h.points)
	}
}

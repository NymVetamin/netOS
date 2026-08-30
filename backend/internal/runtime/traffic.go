package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/system"
)

type TrafficRate struct {
	RXBytes int64 `json:"rx_bytes"`
	TXBytes int64 `json:"tx_bytes"`
	RXBPS   int64 `json:"rx_bps"`
	TXBPS   int64 `json:"tx_bps"`
}

type TrafficPoint struct {
	At         time.Time              `json:"at"`
	Interfaces map[string]TrafficRate `json:"interfaces"`
}

type TrafficHistory struct {
	Path     string
	Interval time.Duration
	Retain   time.Duration
	Collect  func() ([]InterfaceStat, error)
	Now      func() time.Time

	mu     sync.RWMutex
	points []TrafficPoint
	last   *TrafficPoint
}

func NewTrafficHistory(path string, collector *Collector) *TrafficHistory {
	return &TrafficHistory{
		Path: path, Interval: 30 * time.Second, Retain: 7 * 24 * time.Hour,
		Collect: collector.InterfaceStats, Now: time.Now,
	}
}

func (h *TrafficHistory) Run(ctx context.Context) {
	_ = h.load()
	h.sample()
	ticker := time.NewTicker(h.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.sample()
		}
	}
}

func (h *TrafficHistory) sample() {
	stats, err := h.Collect()
	if err != nil {
		return
	}
	now := h.Now().UTC()
	point := TrafficPoint{At: now, Interfaces: map[string]TrafficRate{}}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, stat := range stats {
		rate := TrafficRate{RXBytes: stat.RXBytes, TXBytes: stat.TXBytes}
		if h.last != nil {
			if previous, ok := h.last.Interfaces[stat.Name]; ok {
				seconds := now.Sub(h.last.At).Seconds()
				if seconds > 0 && stat.RXBytes >= previous.RXBytes && stat.TXBytes >= previous.TXBytes {
					rate.RXBPS = int64(float64(stat.RXBytes-previous.RXBytes) * 8 / seconds)
					rate.TXBPS = int64(float64(stat.TXBytes-previous.TXBytes) * 8 / seconds)
				}
			}
		}
		point.Interfaces[stat.Name] = rate
	}
	h.points = append(h.points, point)
	h.last = &point
	h.pruneLocked(now.Add(-h.Retain))
	_ = h.saveLocked()
}

func (h *TrafficHistory) Points(since time.Time, names []string) []TrafficPoint {
	filter := map[string]bool{}
	for _, name := range names {
		if name != "" {
			filter[name] = true
		}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := make([]TrafficPoint, 0)
	for _, point := range h.points {
		if point.At.Before(since) {
			continue
		}
		copyPoint := TrafficPoint{At: point.At, Interfaces: map[string]TrafficRate{}}
		for name, rate := range point.Interfaces {
			if len(filter) == 0 || filter[name] {
				copyPoint.Interfaces[name] = rate
			}
		}
		result = append(result, copyPoint)
	}
	return result
}

func (h *TrafficHistory) pruneLocked(before time.Time) {
	index := sort.Search(len(h.points), func(i int) bool { return !h.points[i].At.Before(before) })
	if index > 0 {
		h.points = append([]TrafficPoint(nil), h.points[index:]...)
	}
}

func (h *TrafficHistory) load() error {
	data, err := os.ReadFile(h.Path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var points []TrafficPoint
	if err := json.Unmarshal(data, &points); err != nil {
		return fmt.Errorf("разбор истории трафика: %w", err)
	}
	sort.Slice(points, func(i, j int) bool { return points[i].At.Before(points[j].At) })
	h.mu.Lock()
	h.points = points
	if len(points) > 0 {
		last := points[len(points)-1]
		h.last = &last
	}
	h.pruneLocked(h.Now().UTC().Add(-h.Retain))
	h.mu.Unlock()
	return nil
}

func (h *TrafficHistory) saveLocked() error {
	data, err := json.Marshal(h.points)
	if err != nil {
		return err
	}
	return system.WriteFileAtomic(h.Path, append(data, '\n'), 0o600)
}

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	mu          sync.RWMutex
	points      []TrafficPoint
	last        *TrafficPoint
	lastCompact time.Time
}

const maxTrafficHistoryBytes = 64 << 20

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
	if h.lastCompact.IsZero() || now.Sub(h.lastCompact) >= 24*time.Hour {
		_ = h.compactLocked(now)
	} else {
		_ = h.appendLocked(point)
	}
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
	info, err := os.Stat(h.Path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() > maxTrafficHistoryBytes {
		return fmt.Errorf("история трафика слишком велика: %d байт", info.Size())
	}
	data, err := os.ReadFile(h.Path)
	if err != nil {
		return err
	}
	var points []TrafficPoint
	legacy := len(bytes.TrimSpace(data)) > 0 && bytes.TrimSpace(data)[0] == '['
	if legacy {
		// Compatibility with the original JSON-array persistence format.
		if err := json.Unmarshal(data, &points); err != nil {
			return fmt.Errorf("разбор истории трафика: %w", err)
		}
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		for scanner.Scan() {
			var point TrafficPoint
			if err := json.Unmarshal(scanner.Bytes(), &point); err != nil {
				return fmt.Errorf("разбор истории трафика: %w", err)
			}
			points = append(points, point)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("чтение истории трафика: %w", err)
		}
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

func (h *TrafficHistory) appendLocked(point TrafficPoint) error {
	if err := os.MkdirAll(filepath.Dir(h.Path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(h.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(point); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (h *TrafficHistory) compactLocked(now time.Time) error {
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	for _, point := range h.points {
		if err := enc.Encode(point); err != nil {
			return err
		}
	}
	if err := system.WriteFileAtomic(h.Path, data.Bytes(), 0o600); err != nil {
		return err
	}
	h.lastCompact = now
	return nil
}

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
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

	mu                 sync.RWMutex
	points             []TrafficPoint
	last               *TrafficPoint
	lastCompact        time.Time
	persistenceBlocked bool
}

const maxTrafficHistoryBytes = 64 << 20

func NewTrafficHistory(path string, collector *Collector) *TrafficHistory {
	return &TrafficHistory{
		Path: path, Interval: 30 * time.Second, Retain: 7 * 24 * time.Hour,
		Collect: collector.InterfaceStats, Now: time.Now,
	}
}

func (h *TrafficHistory) Run(ctx context.Context) {
	err := h.load()
	h.persistenceBlocked = err != nil
	if err != nil {
		log.Printf("история трафика: запись приостановлена до перезапуска: %v", err)
	}
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
	if err := h.record(stats, h.Now().UTC()); err != nil {
		log.Printf("история трафика: ошибка записи, повтор при следующем сборе: %v", err)
	}
}

func (h *TrafficHistory) record(stats []InterfaceStat, now time.Time) error {
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
	index := len(h.points)
	if index > 0 && now.Before(h.points[index-1].At) {
		index = sort.Search(index, func(i int) bool { return h.points[i].At.After(now) })
	}
	h.points = slices.Insert(h.points, index, point)
	h.last = &point
	pruned := h.pruneLocked(now.Add(-h.Retain))
	if h.persistenceBlocked {
		return nil
	}
	var err error
	if h.lastCompact.IsZero() || now.Sub(h.lastCompact) >= 24*time.Hour {
		err = h.compactLocked(now, index-pruned)
	} else {
		err = h.appendLocked(point)
	}
	if err != nil {
		// The append may have left a partial line. Rebuild from retained samples.
		h.lastCompact = time.Time{}
	}
	return err
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

// Window bounds the response independently of the selected history length.
// Rates are averaged within a time bucket, never added across time.
func (h *TrafficHistory) Window(from, to time.Time, names []string, limit int) []TrafficPoint {
	filter := map[string]bool{}
	for _, name := range names {
		if name != "" {
			filter[name] = true
		}
	}
	// Aggregate directly from immutable samples under the read lock. Copying
	// every sample's map first costs far more than the bounded output itself.
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []TrafficPoint{}
	if limit < 2 {
		limit = 2
	}
	step := to.Sub(from) / time.Duration(limit)
	if step < h.Interval {
		step = h.Interval
	}
	if step <= 0 {
		step = 30 * time.Second
	}
	var bucket int64 = -1
	var count int64
	flush := func() {
		if count == 0 {
			return
		}
		p := &out[len(out)-1]
		for name, v := range p.Interfaces {
			v.RXBPS /= count
			v.TXBPS /= count
			p.Interfaces[name] = v
		}
	}
	start := sort.Search(len(h.points), func(i int) bool { return !h.points[i].At.Before(from) })
	for _, p := range h.points[start:] {
		if p.At.After(to) {
			break
		}
		key := int64(p.At.Sub(from) / step)
		if key != bucket {
			flush()
			bucket = key
			count = 0
			out = append(out, TrafficPoint{At: p.At, Interfaces: map[string]TrafficRate{}})
		}
		count++
		target := &out[len(out)-1]
		add := func(name string, v TrafficRate) {
			old := target.Interfaces[name]
			old.RXBPS += v.RXBPS
			old.TXBPS += v.TXBPS
			old.RXBytes = v.RXBytes
			old.TXBytes = v.TXBytes
			target.Interfaces[name] = old
		}
		if len(filter) == 0 {
			for name, v := range p.Interfaces {
				add(name, v)
			}
		} else {
			for name := range filter {
				if v, ok := p.Interfaces[name]; ok {
					add(name, v)
				}
			}
		}
	}
	flush()
	return out
}

func (h *TrafficHistory) pruneLocked(before time.Time) int {
	index := sort.Search(len(h.points), func(i int) bool { return !h.points[i].At.Before(before) })
	if index == 0 {
		return 0
	}
	remaining := h.points[index:]
	if index >= len(remaining) {
		// After a large time jump, release the old backing array.
		h.points = append([]TrafficPoint(nil), remaining...)
	} else {
		clear(h.points[:index])
		h.points = remaining
	}
	return index
}

func (h *TrafficHistory) load() error {
	file, err := os.Open(h.Path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var legacy bool
	for {
		first, err := reader.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if first != ' ' && first != '\t' && first != '\r' && first != '\n' {
			legacy = first == '['
			if err := reader.UnreadByte(); err != nil {
				return err
			}
			break
		}
	}
	var points []TrafficPoint
	cutoff := h.Now().UTC().Add(-h.Retain)
	var last *TrafficPoint
	if legacy {
		data, err := io.ReadAll(io.LimitReader(reader, maxTrafficHistoryBytes+1))
		if err != nil {
			return err
		}
		if len(data) > maxTrafficHistoryBytes {
			return fmt.Errorf("старый массив истории трафика превышает %d байт", maxTrafficHistoryBytes)
		}
		if err := json.Unmarshal(data, &points); err != nil {
			return fmt.Errorf("разбор истории трафика: %w", err)
		}
		if len(points) > 0 {
			point := points[len(points)-1]
			last = &point
		}
	} else {
		// An interrupted append can leave a fragment after the last newline.
		// The first successful sample atomically rewrites the recovered points.
		scanner := bufio.NewScanner(reader)
		scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
			if atEOF && bytes.IndexByte(data, '\n') < 0 && !json.Valid(data) {
				return len(data), nil, nil
			}
			return bufio.ScanLines(data, atEOF)
		})
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		for scanner.Scan() {
			var point TrafficPoint
			if err := json.Unmarshal(scanner.Bytes(), &point); err != nil {
				return fmt.Errorf("разбор истории трафика: %w", err)
			}
			if !point.At.Before(cutoff) {
				points = append(points, point)
			}
			if last == nil {
				last = new(TrafficPoint)
			}
			*last = point
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("чтение истории трафика: %w", err)
		}
	}
	sort.SliceStable(points, func(i, j int) bool { return points[i].At.Before(points[j].At) })
	h.mu.Lock()
	h.points = points
	h.last = last
	h.pruneLocked(cutoff)
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

func (h *TrafficHistory) compactLocked(now time.Time, latest int) error {
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	for i, point := range h.points {
		if i == latest {
			continue
		}
		if err := enc.Encode(point); err != nil {
			return err
		}
	}
	// The final record seeds rate calculation after restart, even if the
	// clock moved back and the last collected sample has an earlier timestamp.
	if latest >= 0 {
		if err := enc.Encode(h.points[latest]); err != nil {
			return err
		}
	}
	if err := system.WriteFileAtomic(h.Path, data.Bytes(), 0o600); err != nil {
		return err
	}
	h.lastCompact = now
	return nil
}

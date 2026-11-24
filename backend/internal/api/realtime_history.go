package api

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	_ "modernc.org/sqlite"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Keep raw seconds on disk in compressed minute blocks. Only the current
// minute is resident. Rewriting that block every ten seconds bounds crash loss
// without fsync or rewriting seven days of history on each measurement.
const secondsPerBlock = 60

type secondHistory struct {
	mu      sync.Mutex
	db      *sql.DB
	reader  *sql.DB
	tail    []realtimeSnapshot
	flushed float64
	pending int
	blockID int64
}

func openSecondHistory(path string) (*secondHistory, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	blockID, err := prepareSecondHistory(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	// A long history cursor must not occupy the sampler's connection. WAL
	// allows this bounded reader pool to keep its snapshot while we flush.
	reader, err := sql.Open("sqlite", path)
	if err != nil {
		db.Close()
		return nil, err
	}
	reader.SetMaxOpenConns(1)
	if _, err = reader.Exec(`PRAGMA busy_timeout=3000;`); err != nil {
		reader.Close()
		db.Close()
		return nil, err
	}
	return &secondHistory{db: db, reader: reader, blockID: blockID}, nil
}

func (h *secondHistory) append(s realtimeSnapshot) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.tail) > 0 && (len(h.tail) >= secondsPerBlock || s.At < h.tail[len(h.tail)-1].At || s.At-h.tail[0].At >= secondsPerBlock) {
		if err := h.flushLocked(); err != nil {
			return err
		}
		h.tail = nil
		h.blockID++
	}
	h.tail = append(h.tail, s)
	h.pending++
	if s.At-h.flushed >= 10 || h.pending >= 10 {
		return h.flushLocked()
	}
	return nil
}

func compareHistoryTime(a, b realtimeSnapshot) int { return cmp.Compare(a.At, b.At) }

func summarize(frames []realtimeSnapshot) realtimeSnapshot {
	result := realtimeSnapshot{Values: []realtimeValue{}}
	if len(frames) == 0 {
		return result
	}
	result.At = frames[0].At
	index := map[string]int{}
	counts := map[string]float64{}
	for _, frame := range frames {
		for _, v := range frame.Values {
			i, ok := index[v.ID]
			if !ok {
				i = len(result.Values)
				index[v.ID] = i
				result.Values = append(result.Values, realtimeValue{ID: v.ID, Name: v.Name, At: result.At})
			}
			if v.RXBPS == nil || v.TXBPS == nil {
				continue
			}
			row := &result.Values[i]
			if row.RXBPS == nil {
				row.RXBPS = new(float64)
				row.TXBPS = new(float64)
				row.RXPeak = new(float64)
				row.TXPeak = new(float64)
			}
			rxPeak, txPeak := *v.RXBPS, *v.TXBPS
			if v.RXPeak != nil {
				rxPeak = *v.RXPeak
			}
			if v.TXPeak != nil {
				txPeak = *v.TXPeak
			}
			if rxPeak > *row.RXPeak {
				*row.RXPeak = rxPeak
			}
			if txPeak > *row.TXPeak {
				*row.TXPeak = txPeak
			}
			weight := v.Seconds
			if weight <= 0 {
				weight = 1
			}
			*row.RXBPS += *v.RXBPS * weight
			*row.TXBPS += *v.TXBPS * weight
			counts[v.ID] += weight
		}
	}
	for i := range result.Values {
		v := &result.Values[i]
		if n := counts[v.ID]; n > 0 {
			*v.RXBPS /= n
			*v.TXBPS /= n
			v.Seconds = n
		}
	}
	return result
}

func decodeHistoryBlock[T any](data []byte) ([]T, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	var frames []T
	err = json.NewDecoder(io.LimitReader(gz, 64<<20)).Decode(&frames)
	return frames, err
}

func encodeHistoryBlock(frames []realtimeSnapshot) ([]byte, []byte, error) {
	var packed bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&packed, gzip.BestSpeed)
	if err := json.NewEncoder(gz).Encode(frames); err != nil {
		return nil, nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, nil, err
	}
	summary, err := json.Marshal(summarize(frames))
	if err != nil {
		return nil, nil, err
	}
	return packed.Bytes(), summary, nil
}

func (h *secondHistory) flushLocked() error {
	if len(h.tail) == 0 {
		return nil
	}
	packed, summary, err := encodeHistoryBlock(h.tail)
	if err != nil {
		return err
	}
	start, end := h.tail[0].At, h.tail[len(h.tail)-1].At
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO seconds(id,start,finish,data,summary) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET start=excluded.start,finish=excluded.finish,data=excluded.data,summary=excluded.summary`, h.blockID, start, end, packed, summary); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM seconds WHERE finish < ?`, end-7*86400); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	h.flushed = end
	h.pending = 0
	return nil
}

func (h *secondHistory) close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := h.flushLocked()
	readerErr := h.reader.Close()
	closeErr := h.db.Close()
	if err != nil {
		return err
	}
	if readerErr != nil {
		return readerErr
	}
	return closeErr
}

func (h *secondHistory) window(ctx context.Context, from, to float64) ([]realtimeSnapshot, int, error) {
	h.mu.Lock()
	tail := append([]realtimeSnapshot(nil), h.tail...)
	blockID := h.blockID
	h.mu.Unlock()
	raw := to-from <= 1800
	// Fetch compressed seconds only when a minute straddles the requested range.
	columns := "start < ?1 OR finish > ?2, CASE WHEN start < ?1 OR finish > ?2 THEN data ELSE summary END"
	step := int(math.Max(1, math.Ceil((to-from)/1440/60))) * 60
	order := "start,id"
	if raw {
		order = "id"
		columns = "1, data"
		step = 1
	}
	// A later flush can persist the captured tail or start another block.
	// The immutable IDs below this boundary belong to earlier observations.
	rows, err := h.reader.QueryContext(ctx, `SELECT `+columns+` FROM seconds INDEXED BY seconds_start WHERE start BETWEEN ?4 AND ?2 AND finish>=?1 AND id<?3 ORDER BY `+order, from, to, blockID, from-secondsPerBlock)
	if err != nil {
		return nil, step, err
	}
	out := []realtimeSnapshot{}
	bucketKey := -1
	var bucket []realtimeSnapshot
	flush := func() {
		if len(bucket) > 0 {
			if !slices.IsSortedFunc(bucket, compareHistoryTime) {
				slices.SortStableFunc(bucket, compareHistoryTime)
			}
			out = append(out, summarize(bucket))
			bucket = nil
		}
	}
	add := func(frame realtimeSnapshot) {
		if frame.At < from || frame.At > to {
			return
		}
		if raw {
			out = append(out, frame)
			return
		}
		key := int((frame.At - from) / float64(step))
		if key != bucketKey {
			flush()
			bucketKey = key
		}
		bucket = append(bucket, frame)
	}
	// Each overview block contributes a single weighted sample. Merge the
	// live block by time, since a clock reset can place it before disk rows.
	clip := func(block []realtimeSnapshot) []realtimeSnapshot {
		for len(block) > 0 && block[0].At < from {
			block = block[1:]
		}
		for len(block) > 0 && block[len(block)-1].At > to {
			block = block[:len(block)-1]
		}
		return block
	}
	tail = clip(tail)
	addDisk := func(frame realtimeSnapshot) {
		if !raw && len(tail) > 0 && tail[0].At < frame.At {
			add(summarize(tail))
			tail = nil
		}
		add(frame)
	}
	var compressed bool
	for rows.Next() {
		var data []byte
		if err = rows.Scan(&compressed, &data); err != nil {
			rows.Close()
			return nil, step, err
		}
		if compressed {
			block, e := decodeHistoryBlock[realtimeSnapshot](data)
			if e != nil {
				rows.Close()
				return nil, step, e
			}
			block = clip(block)
			if raw {
				for _, frame := range block {
					add(frame)
				}
			} else if len(block) > 0 {
				addDisk(summarize(block))
			}
		} else {
			var frame realtimeSnapshot
			if err = json.Unmarshal(data, &frame); err != nil {
				rows.Close()
				return nil, step, err
			}
			addDisk(frame)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, step, err
	}
	if raw {
		out = append(out, tail...)
		if !slices.IsSortedFunc(out, compareHistoryTime) {
			slices.SortStableFunc(out, compareHistoryTime)
		}
	} else {
		if len(tail) > 0 {
			add(summarize(tail))
		}
		flush()
	}
	return out, step, nil
}

func (s *Server) StartSecondHistory(ctx context.Context, path string) error {
	h, err := openSecondHistory(path)
	if err != nil {
		return err
	}
	m := &s.realtime
	ctx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.history = h
	m.stopHistory = cancel
	m.historyDone = make(chan struct{})
	m.running = true
	m.changed = make(chan struct{})
	m.mu.Unlock()
	go func() {
		defer close(m.historyDone)
		s.runRealtimeContext(ctx)
		if err := h.close(); err != nil && s.Logger != nil {
			s.Logger.Warnf("секундная история: %v", err)
		}
	}()
	return nil
}

func (s *Server) StopSecondHistory() {
	m := &s.realtime
	if m.stopHistory != nil {
		m.stopHistory()
		<-m.historyDone
	}
}

func (s *Server) handleSecondHistory(w http.ResponseWriter, r *http.Request) {
	if !anySection(r, false, "dashboard", "traffic") {
		writeError(w, 403, "нет доступа")
		return
	}
	from, to, err := statisticsRange(r)
	if err != nil {
		writeError(w, 400, "%v", err)
		return
	}
	h := s.realtime.history
	if h == nil {
		writeError(w, 503, "секундная история недоступна")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	frames, step, err := h.window(ctx, float64(from.UnixNano())/1e9, float64(to.UnixNano())/1e9)
	if err != nil {
		writeError(w, 500, "не удалось прочитать секундную историю: %s", fmt.Sprint(err))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"points": frames, "interval_seconds": step, "retention_seconds": 7 * 86400})
}

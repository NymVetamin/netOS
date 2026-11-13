package runtime

import (
	"context"
	"database/sql"
	"sort"
	"time"
)

type HistoryLimit struct {
	Kind string `json:"kind"`
	From int64  `json:"from"`
	To   int64  `json:"to"`
}

type HistoryAvailable struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

type historyLimitKey struct {
	kind string
	hour int64
}

func mergeHistoryLimit(dst map[historyLimitKey]HistoryLimit, key historyLimitKey, v HistoryLimit) {
	if old, ok := dst[key]; ok {
		v.From = min(v.From, old.From)
		v.To = max(v.To, old.To)
	}
	dst[key] = v
}

// Hour buckets bound metadata to seven days, not the number of dropped events.
// Multiple losses inside an hour are conservatively represented by their span.
func splitHistoryLimit(kind string, from, to int64, add func(historyLimitKey, HistoryLimit)) {
	if to < from {
		return
	}
	from = max(from, to-7*24*3600)
	for hour := time.Unix(from, 0).UTC().Truncate(time.Hour).Unix(); hour <= to; hour += 3600 {
		add(historyLimitKey{kind, hour}, HistoryLimit{kind, max(from, hour), min(to, hour+3599)})
	}
}

// Caller holds mu. Buffers report immediately; the next successful existing
// transaction persists pending metadata without a write per incoming event.
func (h *ClientHistory) noteLimitLocked(kind string, from, to int64) {
	if h.limits == nil {
		h.limits = map[historyLimitKey]HistoryLimit{}
	}
	if h.pendingLimits == nil {
		h.pendingLimits = map[historyLimitKey]HistoryLimit{}
	}
	splitHistoryLimit(kind, from, to, func(k historyLimitKey, v HistoryLimit) {
		mergeHistoryLimit(h.limits, k, v)
		mergeHistoryLimit(h.pendingLimits, k, v)
	})
}

func (h *ClientHistory) loadLimits() error {
	rows, err := h.db.Query("SELECT kind,hour,first,last FROM history_limits WHERE last>=?", time.Now().Add(-7*24*time.Hour).Unix())
	if err != nil {
		return err
	}
	defer rows.Close()
	h.limits = map[historyLimitKey]HistoryLimit{}
	for rows.Next() {
		var k historyLimitKey
		var v HistoryLimit
		if err = rows.Scan(&k.kind, &k.hour, &v.From, &v.To); err != nil {
			return err
		}
		v.Kind = k.kind
		h.limits[k] = v
	}
	return rows.Err()
}

func writeHistoryLimits(tx *sql.Tx, limits map[historyLimitKey]HistoryLimit) error {
	for k, v := range limits {
		if _, err := tx.Exec(`INSERT INTO history_limits(kind,hour,first,last) VALUES(?,?,?,?)
 ON CONFLICT(kind,hour) DO UPDATE SET first=MIN(first,excluded.first),last=MAX(last,excluded.last)`, k.kind, k.hour, v.From, v.To); err != nil {
			return err
		}
	}
	return nil
}

// Capture only rows actually deleted by a quota. The caller commits these
// markers atomically with deletion and publishes them only after commit.
func deleteHistoryQuota(tx *sql.Tx, kind, query string, limits map[historyLimitKey]HistoryLimit, args ...any) (bool, error) {
	rows, err := tx.Query(query+" RETURNING at", args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	removed := false
	for rows.Next() {
		var at int64
		if err = rows.Scan(&at); err != nil {
			return false, err
		}
		removed = true
		splitHistoryLimit(kind, at, at, func(k historyLimitKey, v HistoryLimit) { mergeHistoryLimit(limits, k, v) })
	}
	return removed, rows.Err()
}

func (h *ClientHistory) reportLimits(from, to int64) []HistoryLimit {
	h.mu.Lock()
	defer h.mu.Unlock()
	byKind := map[string]HistoryLimit{}
	for _, v := range h.limits {
		if v.To < from || v.From > to {
			continue
		}
		if old, ok := byKind[v.Kind]; ok {
			v.From = min(v.From, old.From)
			v.To = max(v.To, old.To)
		}
		byKind[v.Kind] = v
	}
	out := make([]HistoryLimit, 0, len(byKind))
	for _, v := range byKind {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

func (h *ClientHistory) availableHistory(ctx context.Context) (*HistoryAvailable, error) {
	var first, last sql.NullInt64
	// Four index seeks, not MIN+MAX over an expanded history view.
	err := h.db.QueryRowContext(ctx, `SELECT MIN(first),MAX(last) FROM (
 SELECT (SELECT MIN(at) FROM traffic) AS first,(SELECT MAX(at) FROM traffic) AS last
 UNION ALL SELECT (SELECT MIN(at) FROM traffic_idle),(SELECT MAX(at) FROM traffic_idle))`).Scan(&first, &last)
	if err != nil {
		return nil, err
	}
	if !first.Valid || !last.Valid {
		return nil, nil
	}
	return &HistoryAvailable{first.Int64, last.Int64}, nil
}

package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/netos-router/netos/internal/store"
	"strconv"
	"strings"
)

type logCandidate struct {
	id      string
	at      int64
	journal map[string]json.RawMessage
	audit   *store.AuditEntry
}

// Decode a bounded raw batch, retaining noise until the two-source merge has
// consumed it. Filtering before this merge would lose its ordering frontier.
func journalCandidateBatch(raw, anchor string, skipAnchor bool, title string) ([]logCandidate, bool, error) {
	scan := bufio.NewScanner(strings.NewReader(raw))
	scan.Buffer(make([]byte, 4096), 2<<20)
	rows := make([]logCandidate, 0, logScanSize+1)
	checked := anchor == ""
	for scan.Scan() {
		if strings.TrimSpace(scan.Text()) == "" {
			continue
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
			return nil, false, fmt.Errorf("не удалось разобрать запись %s", title)
		}
		var id, stamp string
		_ = json.Unmarshal(row["__CURSOR"], &id)
		_ = json.Unmarshal(row["__REALTIME_TIMESTAMP"], &stamp)
		at, err := strconv.ParseInt(stamp, 10, 64)
		if err != nil || id == "" || len(id) > 1800 || strings.ContainsAny(id, "\r\n\x00") {
			return nil, false, fmt.Errorf("источник %s не вернул время или курсор", title)
		}
		if !checked {
			if id != anchor {
				return nil, true, nil
			}
			checked = true
			if skipAnchor {
				continue
			}
		}
		rows = append(rows, logCandidate{id: id, at: at, journal: row})
		if len(rows) > logScanSize+1 {
			return nil, false, fmt.Errorf("источник %s превысил размер страницы", title)
		}
	}
	if err := scan.Err(); err != nil {
		return nil, false, err
	}
	return rows, !checked, nil
}

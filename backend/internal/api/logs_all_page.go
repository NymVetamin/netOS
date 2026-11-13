package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/system"
)

type allLogPosition struct {
	Journal   [2]allJournalPosition `json:"journal"`
	Files     *dnsFilePosition      `json:"files"`
	MaxID     int64                 `json:"max_id"`
	ID        int64                 `json:"id"`
	AuditDone bool                  `json:"audit_done,omitempty"`
}

func (p allLogPosition) valid() bool {
	if p.Files == nil || !p.Files.valid() || p.MaxID < 0 || p.ID < 0 || p.ID > p.MaxID {
		return false
	}
	size := 0
	for _, stream := range p.Journal {
		if !stream.valid() {
			return false
		}
		size += len(stream.Anchor) + len(stream.Upper) + len(stream.Lower)
	}
	return size <= 3600 && !(p.Journal[0].Done && p.Journal[1].Done && p.AuditDone && p.Files.done())
}

func (s *Server) handleAllLogPage(w http.ResponseWriter, r *http.Request, path string) {
	if r.URL.Query().Get("kind") == "" {
		r = r.Clone(r.Context())
		query := r.URL.Query()
		query.Set("kind", "all")
		r.URL.RawQuery = query.Encode()
	}
	c, err := journalPageRequest(r, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		writeError(w, 400, "%s", err)
		return
	}
	pos := allLogPosition{MaxID: -1}
	if c.All != nil {
		pos = *c.All
	}
	p := journalLogPage{Kind: "all", Entries: []logEntry{}, Warnings: []string{}, From: c.From, CapturedAt: c.To}
	var journal [2][]logCandidate
	var audit []store.AuditEntry
	var files []dnsFileLine
	if !pos.AuditDone {
		if s.Store == nil {
			err = fmt.Errorf("хранилище аудита недоступно")
		} else {
			audit, pos.MaxID, err = s.Store.ReadAccessAuditBatch(r.Context(), pos.MaxID, pos.ID)
		}
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 409, "Запись продолжения аудита удалена; обновите журнал")
			return
		}
		if err != nil {
			p.Incomplete = true
			p.Warnings = append(p.Warnings, "Панель: "+err.Error())
		}
	}
	if pos.Files == nil || !pos.Files.done() {
		var next dnsFilePosition
		files, next, err = readDNSFileBatch(r.Context(), path, pos.Files)
		if errors.Is(err, errDNSFileChanged) {
			writeError(w, 409, "%s", err)
			return
		}
		if err != nil {
			p.Incomplete = true
			p.Warnings = append(p.Warnings, "DNS-файл: "+err.Error())
		} else {
			pos.Files = &next
		}
	}
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	}
	for i := range journal {
		var stale bool
		journal[i], stale, err = readAllJournalBatch(r.Context(), runner, c, &pos.Journal[i], i == 1)
		if stale {
			writeError(w, 409, "Запись продолжения journal удалена; обновите журнал")
			return
		}
		if err != nil {
			p.Incomplete = true
			title := "Службы и подключения"
			if i == 1 {
				title = "Firewall"
			}
			p.Warnings = append(p.Warnings, title+": "+err.Error())
		}
	}
	stale, err := mergeAllLogPage(&p, &c, &pos, journal, audit, files)
	if stale {
		writeError(w, 409, "Нижняя граница journal удалена; обновите журнал")
		return
	}
	if err != nil {
		writeError(w, 502, "%s", err)
		return
	}
	writeJSON(w, 200, p)
}

func mergeAllLogPage(p *journalLogPage, c *journalLogCursor, pos *allLogPosition, journal [2][]logCandidate, audit []store.AuditEntry, files []dnsFileLine) (bool, error) {
	indices := [4]int{}
	from, to := c.From.UnixMicro(), c.To.UnixMicro()
	fileHead := -1
	referenceTime := c.To.In(time.Local)
	var fileAt int64
	var fileTime string
	fileKnown, unknown := false, false
	for p.Scanned < logScanSize && len(p.Entries) < logPageSize {
		// File batches can end at a byte boundary before 501 rows. Read its
		// unseen next head before choosing older records from other streams.
		if !p.Incomplete && indices[3] == len(files) && pos.Files != nil && !pos.Files.done() {
			break
		}
		if indices[3] < len(files) && fileHead != indices[3] {
			fileHead = indices[3]
			fileAt, fileKnown = 0, false
			fileTime = dnsLineTime(files[fileHead].Text, referenceTime)
			if at, err := time.Parse(time.RFC3339Nano, fileTime); err == nil {
				fileAt, fileKnown = at.UnixMicro(), true
			}
		}
		chosen := -1
		var at int64
		for i := 0; i < 4; i++ {
			var next int64
			switch i {
			case 0, 1:
				if indices[i] == len(journal[i]) || pos.Journal[i].Done {
					continue
				}
				next = journal[i][indices[i]].at
			case 2:
				if indices[i] == len(audit) {
					continue
				}
				next = audit[indices[i]].At.UnixMicro()
			case 3:
				if indices[i] == len(files) {
					continue
				}
				next = fileAt
			}
			if chosen < 0 || next > at {
				chosen, at = i, next
			}
		}
		if chosen < 0 {
			break
		}
		index := indices[chosen]
		indices[chosen]++
		p.Scanned++
		var entry logEntry
		keep, known := true, true
		switch chosen {
		case 0, 1:
			row := journal[chosen][index]
			stream := &pos.Journal[chosen]
			stream.Anchor, stream.Upper = row.id, ""
			if row.id == stream.Lower {
				*stream = allJournalPosition{Done: true}
			}
			entry, keep = allJournalEntry(row.journal, chosen == 1)
			entry.ID = "journal:" + row.id
		case 2:
			row := audit[index]
			pos.ID = row.ID
			var err error
			entry, err = panelAccessEntry(row)
			if err != nil {
				p.Incomplete = true
				p.Warnings = append(p.Warnings, "Не удалось разобрать запись аудита")
				return false, nil
			}
			entry.ID = "audit:" + strconv.FormatInt(row.ID, 10)
		case 3:
			row := files[index]
			pos.Files.Next = row.Next
			known = fileKnown
			entry = logEntry{ID: "file:" + row.ID, Time: fileTime, Source: "dns", Unit: "dns.log", Message: row.Text}
			keep = isDNSQuery(row.Text)
		}
		if !keep || (known && (at < from || at > to)) {
			continue
		}
		result := entry.Result
		if result == "" {
			result = entry.Severity
		}
		if result == "" {
			result = "info"
		}
		if c.Result != "" && result != c.Result && entry.Severity != c.Result {
			continue
		}
		if c.Object != "" && !strings.Contains(strings.ToLower(entry.User+" "+entry.Address+" "+entry.Protocol+" "+entry.Server+" "+entry.Unit+" "+entry.Message), c.Object) {
			continue
		}
		unknown = unknown || !known
		p.Entries = append(p.Entries, entry)
	}
	if unknown {
		p.Warnings = append(p.Warnings, "Есть записи без времени: их принадлежность выбранному периоду неизвестна")
	}
	if p.Incomplete {
		return false, nil
	}
	for i, stream := range pos.Journal {
		if !stream.Done && indices[i] == len(journal[i]) {
			return true, nil
		}
	}
	if indices[2] == len(audit) {
		pos.AuditDone = true
	}
	if !pos.Journal[0].Done || !pos.Journal[1].Done || !pos.AuditDone || !pos.Files.done() {
		if !pos.valid() {
			return false, fmt.Errorf("источники вернули слишком большие или некорректные границы снимка")
		}
		c.All = pos
		encoded, _ := json.Marshal(c)
		p.Next = base64.RawURLEncoding.EncodeToString(encoded)
		if len(p.Next) > 8192 {
			return false, fmt.Errorf("курсор общего журнала слишком длинный")
		}
	}
	return false, nil
}

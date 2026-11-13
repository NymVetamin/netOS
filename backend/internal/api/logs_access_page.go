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

type accessLogPosition struct {
	Version     int    `json:"version"`
	MaxID       int64  `json:"max_id"`
	ID          int64  `json:"id"`
	AuditDone   bool   `json:"audit_done,omitempty"`
	JournalDone bool   `json:"journal_done,omitempty"`
	Upper       string `json:"upper,omitempty"`
	Lower       string `json:"lower,omitempty"`
}

func (p accessLogPosition) valid(anchor string) bool {
	return p.Version == 1 && p.MaxID >= 0 && p.ID >= 0 && p.ID <= p.MaxID && len(anchor)+len(p.Upper)+len(p.Lower) <= 4096 && !strings.ContainsAny(p.Upper+p.Lower, "\r\n\x00") &&
		!(anchor != "" && p.Upper != "") && !(p.AuditDone && p.JournalDone) &&
		(p.JournalDone || (p.Lower != "" && (anchor != "" || p.Upper != ""))) && (p.ID > 0 || anchor != "" || p.JournalDone)
}

func (s *Server) handleAccessLogPage(w http.ResponseWriter, r *http.Request) {
	c, err := journalPageRequest(r, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		writeError(w, 400, "%s", err)
		return
	}
	// Earlier cursors froze an SSH-only lower boundary. Reusing it after
	// adding netosd could silently omit older panel events in the interval.
	pos := accessLogPosition{Version: 1, MaxID: -1}
	if c.Access != nil {
		pos = *c.Access
	}
	p := journalLogPage{Kind: "access", Entries: []logEntry{}, Warnings: []string{}, From: c.From, CapturedAt: c.To}
	var journal, audit []logCandidate
	if !pos.AuditDone {
		var rows []store.AuditEntry
		if s.Store == nil {
			err = fmt.Errorf("хранилище аудита недоступно")
		} else {
			rows, pos.MaxID, err = s.Store.ReadAccessAuditBatch(r.Context(), pos.MaxID, pos.ID)
		}
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 409, "Запись продолжения аудита удалена; обновите журнал")
			return
		}
		if err != nil {
			p.Incomplete = true
			p.Warnings = append(p.Warnings, "Панель: не удалось прочитать аудит: "+err.Error())
		} else {
			audit = make([]logCandidate, len(rows))
			for i := range rows {
				audit[i] = logCandidate{at: rows[i].At.UnixMicro(), audit: &rows[i]}
			}
		}
	}
	if !pos.JournalDone {
		runner := s.StorageRunner
		if runner == nil {
			runner = &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
		}
		if pos.Lower == "" {
			// A cursor cannot be combined with --since. Freeze the first record
			// in the interval, rather than scanning the archive beyond it or
			// stopping on an arbitrary old timestamp after a clock adjustment.
			raw, readErr := runner.Run(r.Context(), "journalctl", "--no-pager", "--quiet", "-o", "json", "-u", "ssh.service", "-u", "sshd.service", "-u", "netosd.service", "--since="+journalPageTime(c.From), "--until="+journalPageTime(c.To), "--output-fields=__CURSOR,__REALTIME_TIMESTAMP", "-n", "+1")
			var first []logCandidate
			if readErr == nil {
				first, _, readErr = journalCandidateBatch(raw, "", false, "доступа")
				if len(first) > 1 {
					readErr = fmt.Errorf("источник доступа вернул несколько границ периода")
				}
			}
			if readErr != nil {
				p.Incomplete = true
				p.Warnings = append(p.Warnings, "Журнал доступа: не удалось определить границу периода: "+readErr.Error())
			} else if len(first) == 0 {
				pos.JournalDone = true
			} else {
				pos.Lower = first[0].id
			}
		}
		if pos.Lower != "" && !pos.JournalDone {
			anchor := c.Anchor
			if anchor == "" {
				anchor = pos.Upper
			}
			limit := logScanSize + 1
			if c.Anchor != "" {
				limit++
			}
			args := []string{"--no-pager", "--quiet", "-o", "json", "--reverse", "-u", "ssh.service", "-u", "sshd.service", "-u", "netosd.service", "--until=" + journalPageTime(c.To), "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER", "-n", strconv.Itoa(limit)}
			if anchor != "" {
				args = append(args, "--cursor="+anchor)
			} else {
				args = append(args, "--since="+journalPageTime(c.From))
			}
			raw, readErr := runner.Run(r.Context(), "journalctl", args...)
			stale := false
			if readErr == nil {
				journal, stale, readErr = journalCandidateBatch(raw, anchor, c.Anchor != "", "доступа")
			}
			if stale {
				writeError(w, 409, "Запись продолжения доступа удалена; обновите журнал")
				return
			}
			if readErr != nil {
				p.Incomplete = true
				p.Warnings = append(p.Warnings, "Журнал доступа: не удалось прочитать журнал: "+readErr.Error())
			} else if anchor == "" && len(journal) > 0 {
				pos.Upper = journal[0].id
			}
		}
	}
	if mergeAccessPage(&p, &c, &pos, journal, audit) {
		writeError(w, 409, "Нижняя граница журнала доступа удалена; обновите журнал")
		return
	}
	writeJSON(w, 200, p)
}

func mergeAccessPage(p *journalLogPage, c *journalLogCursor, pos *accessLogPosition, journal, audit []logCandidate) bool {
	i, j := 0, 0
	from, to := c.From.UnixMicro(), c.To.UnixMicro()
	for p.Scanned < logScanSize && len(p.Entries) < logPageSize && (i < len(journal) || j < len(audit)) {
		var row logCandidate
		if i < len(journal) && (j == len(audit) || journal[i].at >= audit[j].at) {
			row = journal[i]
			i++
			c.Anchor = row.id
			pos.Upper = ""
			if row.id == pos.Lower {
				pos.JournalDone = true
				journal = journal[:i]
			}
		} else {
			row = audit[j]
			j++
			pos.ID = row.audit.ID
		}
		p.Scanned++
		if row.at < from || row.at > to {
			continue
		}
		var e logEntry
		keep := true
		if row.audit != nil {
			var err error
			e, err = panelAccessEntry(*row.audit)
			if err != nil {
				p.Incomplete = true
				p.Warnings = append(p.Warnings, "Не удалось разобрать запись аудита")
				break
			}
			e.ID = "audit:" + strconv.FormatInt(row.audit.ID, 10)
		} else {
			e, keep = journalLogEntry(row.journal, "access")
			e.ID = "journal:" + row.id
		}
		if !keep || (c.Result != "" && e.Result != c.Result) {
			continue
		}
		if c.Object != "" && !strings.Contains(strings.ToLower(e.User+" "+e.Address+" "+e.Protocol+" "+e.Unit), c.Object) {
			continue
		}
		p.Entries = append(p.Entries, e)
	}
	// Incomplete pages are previews only. Never publish any advanced position.
	if p.Incomplete {
		return false
	}
	if i == len(journal) && !pos.JournalDone {
		return true
	}
	if pos.JournalDone {
		pos.Upper = ""
		pos.Lower = ""
		c.Anchor = ""
	}
	if j == len(audit) {
		pos.AuditDone = true
	}
	if !pos.JournalDone || !pos.AuditDone {
		c.Access = pos
		encoded, _ := json.Marshal(c)
		p.Next = base64.RawURLEncoding.EncodeToString(encoded)
	}
	return false
}

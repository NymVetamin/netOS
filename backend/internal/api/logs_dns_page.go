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

	"github.com/netos-router/netos/internal/system"
)

type dnsLogPosition struct {
	Files       *dnsFilePosition `json:"files"`
	Upper       string           `json:"upper,omitempty"`
	Lower       string           `json:"lower,omitempty"`
	JournalDone bool             `json:"journal_done,omitempty"`
}

func (p dnsLogPosition) valid(anchor string) bool {
	return p.Files != nil && p.Files.valid() && len(anchor)+len(p.Upper)+len(p.Lower) <= 3600 && !strings.ContainsAny(p.Upper+p.Lower, "\r\n\x00") && !(anchor != "" && p.Upper != "") && (p.JournalDone || (p.Lower != "" && (anchor != "" || p.Upper != "")))
}
func (p dnsFilePosition) done() bool {
	if p.Next.Offset != 0 {
		return false
	}
	for i := p.Next.File + 1; i < 4; i++ {
		if p.Files[i].Size != 0 {
			return false
		}
	}
	return true
}

func (s *Server) handleDNSLogPage(w http.ResponseWriter, r *http.Request, path string) {
	c, err := journalPageRequest(r, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		writeError(w, 400, "%s", err)
		return
	}
	pos := dnsLogPosition{}
	if c.DNS != nil {
		pos = *c.DNS
	}
	p := journalLogPage{Kind: "dns", Entries: []logEntry{}, Warnings: []string{}, From: c.From, CapturedAt: c.To}
	var fileRows []dnsFileLine
	if pos.Files == nil || !pos.Files.done() {
		var next dnsFilePosition
		fileRows, next, err = readDNSFileBatch(r.Context(), path, pos.Files)
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
	var journal []logCandidate
	if !pos.JournalDone {
		runner := s.StorageRunner
		if runner == nil {
			runner = &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
		}
		base := []string{"--no-pager", "--quiet", "-o", "json", "-u", "netos-unbound.service", "-u", "dnsmasq.service", "-u", "netos-dnsmasq.service", "-u", "netos-dnsproxy.service", "--until=" + journalPageTime(c.To)}
		if pos.Lower == "" {
			raw, e := runner.Run(r.Context(), "journalctl", append(base, "--since="+journalPageTime(c.From), "--output-fields=__CURSOR,__REALTIME_TIMESTAMP", "-n", "+1")...)
			var first []logCandidate
			if e == nil {
				first, _, e = journalCandidateBatch(raw, "", false, "DNS")
				if len(first) > 1 {
					e = fmt.Errorf("несколько нижних границ периода")
				}
			}
			if e != nil {
				p.Incomplete = true
				p.Warnings = append(p.Warnings, "DNS journal: "+e.Error())
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
			args := append(base, "--reverse", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER", "-n", strconv.Itoa(limit))
			if anchor != "" {
				args = append(args, "--cursor="+anchor)
			} else {
				args = append(args, "--since="+journalPageTime(c.From))
			}
			raw, e := runner.Run(r.Context(), "journalctl", args...)
			stale := false
			if e == nil {
				journal, stale, e = journalCandidateBatch(raw, anchor, c.Anchor != "", "DNS")
			}
			if stale {
				writeError(w, 409, "Граница DNS journal удалена; обновите журнал")
				return
			}
			if e != nil {
				p.Incomplete = true
				p.Warnings = append(p.Warnings, "DNS journal: "+e.Error())
			} else if anchor == "" && len(journal) > 0 {
				pos.Upper = journal[0].id
			}
		}
	}
	// Parse only heads needed by this merge, once each and outside the lock.
	referenceTime := c.To.In(time.Local)
	from, to := c.From.UnixMicro(), c.To.UnixMicro()
	fileHead := -1
	fileTime := ""
	var fileAt int64
	fileKnown := false
	i, j := 0, 0
	unknown := false
	for p.Scanned < logScanSize && len(p.Entries) < logPageSize && (i < len(journal) || j < len(fileRows)) {
		// A byte-limited file batch may end before its source does. Its unseen
		// head must be read before more journal entries can be merged.
		if !p.Incomplete && j == len(fileRows) && pos.Files != nil && !pos.Files.done() {
			break
		}
		if j < len(fileRows) && fileHead != j {
			fileHead = j
			fileAt = 0
			fileKnown = false
			fileTime = dnsLineTime(fileRows[j].Text, referenceTime)
			if at, e := time.Parse(time.RFC3339Nano, fileTime); e == nil {
				fileAt = at.UnixMicro()
				fileKnown = true
			}
		}
		var entry logEntry
		var at int64
		keep := false
		known := true
		if i < len(journal) && (j == len(fileRows) || journal[i].at >= fileAt) {
			row := journal[i]
			i++
			at = row.at
			c.Anchor = row.id
			pos.Upper = ""
			if row.id == pos.Lower {
				pos.JournalDone = true
				journal = journal[:i]
			}
			entry, keep = journalLogEntry(row.journal, "dns")
			entry.ID = "journal:" + row.id
		} else {
			row := fileRows[j]
			at = fileAt
			known = fileKnown
			pos.Files.Next = row.Next
			entry = logEntry{ID: "file:" + row.ID, Time: fileTime, Source: "dns", Unit: "dns.log", Message: row.Text}
			keep = isDNSQuery(row.Text)
			j++
		}
		p.Scanned++
		if !keep || (known && (at < from || at > to)) {
			continue
		}
		if c.Object != "" && !strings.Contains(strings.ToLower(entry.Message), c.Object) {
			continue
		}
		if !known {
			unknown = true
		}
		p.Entries = append(p.Entries, entry)
	}
	if unknown {
		p.Warnings = append(p.Warnings, "Есть записи без времени: их принадлежность выбранному периоду неизвестна")
	}
	if !p.Incomplete {
		if i == len(journal) && !pos.JournalDone {
			writeError(w, 409, "Нижняя граница DNS journal удалена; обновите журнал")
			return
		}
		if pos.JournalDone {
			pos.Upper = ""
			pos.Lower = ""
			c.Anchor = ""
		}
		if !pos.JournalDone || !pos.Files.done() {
			c.DNS = &pos
			encoded, _ := json.Marshal(c)
			p.Next = base64.RawURLEncoding.EncodeToString(encoded)
		}
	}
	writeJSON(w, 200, p)
}

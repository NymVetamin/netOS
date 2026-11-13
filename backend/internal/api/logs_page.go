package api

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/system"
)

const logPageSize = 100
const logScanSize = 500

type vpnLogCursor struct {
	Anchor string    `json:"anchor"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Result string    `json:"result"`
	Object string    `json:"object"`
}

type vpnLogPage struct {
	Kind       string     `json:"kind"`
	Entries    []logEntry `json:"entries"`
	Warnings   []string   `json:"warnings"`
	CapturedAt time.Time  `json:"captured_at"`
	From       time.Time  `json:"from"`
	Next       string     `json:"next_cursor,omitempty"`
	Scanned    int        `json:"scanned"`
}

func vpnPageRequest(r *http.Request, now time.Time) (vpnLogCursor, error) {
	q := r.URL.Query()
	c := vpnLogCursor{From: now.Add(-24 * time.Hour), To: now, Result: q.Get("result"), Object: strings.ToLower(strings.TrimSpace(q.Get("object")))}
	if token := q.Get("cursor"); token != "" {
		if len(token) > 8192 {
			return c, fmt.Errorf("курсор журнала слишком длинный")
		}
		data, err := base64.RawURLEncoding.DecodeString(token)
		c = vpnLogCursor{}
		if err != nil || json.Unmarshal(data, &c) != nil || c.Anchor == "" || len(c.Anchor) > 4096 || strings.ContainsAny(c.Anchor, "\r\n\x00") {
			return c, fmt.Errorf("неверный курсор журнала; обновите журнал")
		}
		// A continuation belongs to its original filters and time interval.
		if c.Result != q.Get("result") || c.Object != strings.ToLower(strings.TrimSpace(q.Get("object"))) {
			return c, fmt.Errorf("фильтры курсора изменились; обновите журнал")
		}
	}
	for _, item := range []struct {
		key    string
		target *time.Time
	}{{"from", &c.From}, {"to", &c.To}} {
		if value := q.Get(item.key); value != "" {
			t, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || (c.Anchor != "" && !t.Equal(*item.target)) {
				return c, fmt.Errorf("неверный период журнала")
			}
			*item.target = t
		}
	}
	if c.From.IsZero() || !c.From.Before(c.To) || c.To.Sub(c.From) > 31*24*time.Hour || c.To.After(now.Add(time.Minute)) {
		return c, fmt.Errorf("выберите период до 31 дня, не позднее текущего времени")
	}
	if c.Result != "" && c.Result != "success" && c.Result != "failure" && c.Result != "info" {
		return c, fmt.Errorf("неизвестный результат события")
	}
	if len(c.Object) > 128 {
		return c, fmt.Errorf("фильтр объекта слишком длинный")
	}
	return c, nil
}

func journalPageTime(t time.Time) string {
	return "@" + strconv.FormatInt(t.Unix(), 10) + "." + fmt.Sprintf("%06d", t.Nanosecond()/1000)
}

func (s *Server) handleVPNLogPage(w http.ResponseWriter, r *http.Request) {
	c, err := vpnPageRequest(r, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err.Error())
		return
	}
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	}
	limit := logScanSize + 1
	args := []string{"--no-pager", "--quiet", "-o", "json", "--reverse", "--until=" + journalPageTime(c.To), "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,_SYSTEMD_UNIT,IKE_SA_NAME", "-u", "netos-ocserv-srv*.service", "-u", "netos-strongswan.service", "-u", "netos-vpn-l2tp-srv*.service"}
	if c.Anchor != "" {
		args = append(args, "--cursor="+c.Anchor)
		limit++
	} else {
		args = append(args, "--since="+journalPageTime(c.From))
	}
	args = append(args, "-n", strconv.Itoa(limit))
	raw, err := runner.Run(r.Context(), "journalctl", args...)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Не удалось прочитать журнал VPN: %s", err.Error())
		return
	}
	p, stale, err := readVPNLogPage(raw, c)
	if stale {
		writeError(w, http.StatusConflict, "Запись продолжения больше недоступна; обновите журнал")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "%s", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func readVPNLogPage(raw string, c vpnLogCursor) (vpnLogPage, bool, error) {
	p := vpnLogPage{Kind: "vpn", Entries: []logEntry{}, Warnings: []string{}, CapturedAt: c.To, From: c.From}
	scan := bufio.NewScanner(strings.NewReader(raw))
	scan.Buffer(make([]byte, 4096), 2<<20)
	anchorSeen := c.Anchor == ""
	last := c.Anchor
	from, to := c.From.UnixMicro(), c.To.UnixMicro()
	for scan.Scan() {
		if len(strings.TrimSpace(scan.Text())) == 0 {
			continue
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
			return p, false, fmt.Errorf("не удалось разобрать запись журнала")
		}
		var id string
		_ = json.Unmarshal(row["__CURSOR"], &id)
		if id == "" || len(id) > 4096 {
			return p, false, fmt.Errorf("источник не вернул курсор записи")
		}
		if !anchorSeen {
			if id != c.Anchor {
				return p, true, nil
			}
			anchorSeen = true
			continue
		}
		if p.Scanned == logScanSize || len(p.Entries) == logPageSize {
			c.Anchor = last
			data, _ := json.Marshal(c)
			p.Next = base64.RawURLEncoding.EncodeToString(data)
			break
		}
		p.Scanned++
		last = id
		// journalctl forbids --since together with --cursor. Apply the same
		// lower time boundary while walking the continuation in reverse order.
		var timestamp string
		_ = json.Unmarshal(row["__REALTIME_TIMESTAMP"], &timestamp)
		us, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return p, false, fmt.Errorf("источник не вернул время записи")
		}
		if us < from {
			break
		}
		if us > to {
			continue
		}
		e, keep := journalLogEntry(row, "vpn")
		e.ID = id
		if !keep || (c.Result != "" && e.Result != c.Result) {
			continue
		}
		if c.Object != "" && !strings.Contains(strings.ToLower(e.Server+" "+e.Protocol+" "+e.User+" "+e.Address+" "+e.Unit), c.Object) {
			continue
		}
		p.Entries = append(p.Entries, e)
	}
	if err := scan.Err(); err != nil {
		return p, false, fmt.Errorf("не удалось прочитать страницу журнала: %w", err)
	}
	if !anchorSeen {
		return p, true, nil
	}
	// Keep journal cursor order instead of sorting each page independently;
	// the cursor also disambiguates records with equal timestamps.
	return p, false, nil
}

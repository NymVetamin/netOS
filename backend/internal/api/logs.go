package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/netos-router/netos/internal/system"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type logEntry struct {
	Time    string `json:"time"`
	Source  string `json:"source"`
	Unit    string `json:"unit"`
	Message string `json:"message"`
}

// Query records only: service lifecycle, resolver statistics and replies are not queries.
var dnsmasqQuery = regexp.MustCompile(`\bquery\[[^\]]+\]\s+\S+\s+from\s+\S+`)
var unboundQuery = regexp.MustCompile(`(?:info:|query:)\s+(\S+)\s+\S+\s+[A-Z0-9]+\s+(?:IN|CH|HS|CLASS[0-9]+)\s*$`)
var dnsproxyQuestion = regexp.MustCompile(`^;[^;\s]+\s+(?:IN|CH|HS|CLASS[0-9]+)\s+[A-Z0-9]+\s*$`)
var dnsproxyLine = regexp.MustCompile(`\bline=("(?:\\.|[^"\\])*"|\S+)`)

func isDNSQuery(message string) bool {
	if dnsmasqQuery.MatchString(message) {
		return true
	}
	if m := unboundQuery.FindStringSubmatch(message); len(m) > 1 && net.ParseIP(m[1]) != nil {
		return true
	}
	// dnsproxy emits the DNS packet as structured, numbered lines. Keep its incoming question only.
	if strings.Contains(message, "msg=in ") || strings.Contains(message, "msg=\"in\" ") || strings.Contains(message, " in line_num=") {
		m := dnsproxyLine.FindStringSubmatch(message)
		if len(m) > 1 {
			line := m[1]
			if strings.HasPrefix(line, "\"") {
				line, _ = strconv.Unquote(line)
			}
			return dnsproxyQuestion.MatchString(line)
		}
	}
	if i := strings.Index(message, "in: "); i >= 0 {
		return dnsproxyQuestion.MatchString(strings.TrimSpace(message[i+4:]))
	}
	return false
}

func parseJournalEntries(raw, source string) ([]logEntry, error) {
	result := []logEntry{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return result, fmt.Errorf("не удалось разобрать запись журнала")
		}
		field := func(k string) string { var v string; _ = json.Unmarshal(row[k], &v); return v }
		message := field("MESSAGE")
		if message == "" {
			continue
		}
		if source == "firewall" && !strings.Contains(message, "netos ") {
			continue
		}
		unit := field("_SYSTEMD_UNIT")
		if unit == "" {
			unit = field("SYSLOG_IDENTIFIER")
		}
		ts := ""
		if us, err := strconv.ParseInt(field("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
			ts = time.UnixMicro(us).UTC().Format(time.RFC3339Nano)
		}
		query := isDNSQuery(message)
		if source == "dns" && !query || source == "services" && query {
			continue
		}
		result = append(result, logEntry{Time: ts, Source: source, Unit: unit, Message: message})
	}
	return result, scanner.Err()
}
func dnsLineTime(line string, now time.Time) string {
	for _, layout := range []string{"2006/01/02 15:04:05.000000", "2006/01/02 15:04:05", "2006-01-02 15:04:05", "Jan _2 15:04:05"} {
		if len(line) < len(layout) {
			continue
		}
		if t, err := time.ParseInLocation(layout, line[:len(layout)], now.Location()); err == nil {
			if t.Year() == 0 {
				t = t.AddDate(now.Year(), 0, 0)
				if t.After(now.Add(24 * time.Hour)) {
					t = t.AddDate(-1, 0, 0)
				}
			}
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	fields := strings.Fields(line)
	if len(fields) > 0 {
		if t, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	return ""
}
func readDNSLog(path string, now time.Time) ([]logEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("источник DNS не является обычным файлом")
	}
	const maxBytes int64 = 256 << 10
	offset := stat.Size() - maxBytes
	if offset < 0 {
		offset = 0
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if offset > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > 300 {
		lines = lines[len(lines)-300:]
	}
	result := []logEntry{}
	for _, line := range lines {
		if isDNSQuery(line) {
			result = append(result, logEntry{Time: dnsLineTime(line, now), Source: "dns", Unit: "dns.log", Message: line})
		}
	}
	return result, nil
}
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !may(r, "diagnostics", false) {
		writeError(w, http.StatusForbidden, "журналы доступны только администратору")
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "all"
	}
	if kind != "all" && kind != "dns" && kind != "firewall" && kind != "services" {
		writeError(w, http.StatusBadRequest, "неизвестный журнал")
		return
	}
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 5 * time.Second}
	}
	entries := []logEntry{}
	warnings := []string{}
	now := time.Now()
	for _, src := range []string{"dns", "firewall", "services"} {
		if kind != "all" && kind != src {
			continue
		}
		args := []string{"--no-pager", "--quiet", "-o", "json", "-n", "300", "--output-fields=__REALTIME_TIMESTAMP,MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER"}
		switch src {
		case "dns":
			args = append(args, "-u", "netos-unbound.service", "-u", "dnsmasq.service", "-u", "netos-dnsmasq.service", "-u", "netos-dnsproxy.service")
		case "firewall":
			args = append(args, "-k", "--grep=netos ")
		case "services":
			args = append(args, "-u", "netos*.service")
		}
		raw, err := runner.Run(r.Context(), "journalctl", args...)
		// journalctl --grep exits 1 without stderr when no entries match.
		if src == "firewall" && emptyJournalMatch(raw, err) {
			err = nil
		}
		if err != nil {
			warnings = append(warnings, src+": не удалось прочитать journal: "+err.Error())
		} else {
			rows, parseErr := parseJournalEntries(raw, src)
			if parseErr != nil {
				warnings = append(warnings, src+": "+parseErr.Error())
			}
			entries = append(entries, rows...)
		}
		if src == "dns" {
			rows, err := readDNSLog("/var/log/netos/dns.log", now)
			if err != nil && !os.IsNotExist(err) {
				warnings = append(warnings, "Не удалось прочитать dns.log: "+err.Error())
			} else {
				entries = append(entries, rows...)
			}
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Time == "" {
			return false
		}
		if entries[j].Time == "" {
			return true
		}
		a, _ := time.Parse(time.RFC3339Nano, entries[i].Time)
		b, _ := time.Parse(time.RFC3339Nano, entries[j].Time)
		if kind == "dns" {
			return a.After(b)
		}
		return a.Before(b)
	})
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "warnings": warnings, "captured_at": now.UTC().Format(time.RFC3339), "kind": kind})
}

func emptyJournalMatch(raw string, err error) bool {
	var status interface{ ExitCode() int }
	return err != nil && errors.As(err, &status) && status.ExitCode() == 1 && strings.TrimSpace(raw) == "" && strings.HasSuffix(strings.TrimSpace(err.Error()), "exit status 1:")
}

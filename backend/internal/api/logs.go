package api

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type logEntry struct {
	ID       string `json:"id,omitempty"`
	Time     string `json:"time"`
	Source   string `json:"source"`
	Unit     string `json:"unit"`
	Message  string `json:"message"`
	Event    string `json:"event,omitempty"`
	Severity string `json:"severity,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	User     string `json:"user,omitempty"`
	Address  string `json:"address,omitempty"`
	Result   string `json:"result,omitempty"`
	Server   string `json:"server,omitempty"`
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
	if strings.Contains(message, "msg=in ") || strings.Contains(message, "msg=\"in\" ") || strings.Contains(message, " in line_num=") ||
		strings.HasPrefix(message, "DEBUG in prefix=dnsproxy ") || strings.Contains(message, " DEBUG in prefix=dnsproxy ") {
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

func journalLogEntry(row map[string]json.RawMessage, source string) (logEntry, bool) {
	field := func(k string) string { var v string; _ = json.Unmarshal(row[k], &v); return v }
	message := field("MESSAGE")
	if message == "" {
		return logEntry{}, false
	}
	if source == "firewall" && !strings.Contains(message, "netos ") {
		return logEntry{}, false
	}
	unit := field("_SYSTEMD_UNIT")
	if unit == "" {
		unit = field("SYSLOG_IDENTIFIER")
	}
	ts := ""
	if us, err := strconv.ParseInt(field("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
		ts = time.UnixMicro(us).UTC().Format(time.RFC3339Nano)
	}
	if source == "dns" && !isDNSQuery(message) {
		return logEntry{}, false
	}
	entry := logEntry{Time: ts, Source: source, Unit: unit, Message: message}
	if source == "all" {
		return classifyAllUnitEntry(entry, field)
	}
	if source == "services" {
		var keep bool
		entry.Unit, entry.Event, entry.Severity, keep = serviceLogFields(field, message)
		if !keep {
			return logEntry{}, false
		}
	}
	if source == "access" && !sshLogFields(&entry) {
		return logEntry{}, false
	}
	if source == "vpn" {
		keep := false
		if entry.Unit == "netos-strongswan.service" {
			keep = ikeLogFields(&entry, field)
		} else {
			keep = vpnLogFields(&entry) || l2tpLogFields(&entry)
		}
		if !keep {
			return logEntry{}, false
		}
	}
	return entry, true
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
	if kind != "all" && kind != "dns" && kind != "firewall" && kind != "services" && kind != "access" && kind != "vpn" {
		writeError(w, http.StatusBadRequest, "неизвестный журнал")
		return
	}
	if kind == "access" {
		s.handleAccessLogPage(w, r)
		return
	}
	if kind == "dns" {
		s.handleDNSLogPage(w, r, "/var/log/netos/dns.log")
		return
	}
	if kind == "vpn" || kind == "services" || kind == "firewall" {
		s.handleJournalLogPage(w, r)
		return
	}
	s.handleAllLogPage(w, r, "/var/log/netos/dns.log")
}

package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netos-router/netos/internal/eventlog"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/system"
)

// logWait bounds one long poll; logBatch collects a burst into one response,
// so a busy topic costs a viewer at most a few requests per second.
const (
	logWait  = 25 * time.Second
	logBatch = 250 * time.Millisecond
)

// handleLogs returns the newest events (after=0) or waits for events newer
// than after, the same long-poll scheme as the realtime traffic chart.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !may(r, "diagnostics", false) {
		writeError(w, http.StatusForbidden, "журналы доступны только администратору")
		return
	}
	q := r.URL.Query()
	topic := q.Get("topic")
	if topic == "" {
		topic = "all"
	}
	var after uint64
	if raw := q.Get("after"); raw != "" {
		var err error
		if after, err = strconv.ParseUint(raw, 10, 64); err != nil {
			writeError(w, http.StatusBadRequest, "некорректный номер события")
			return
		}
	}
	epoch := q.Get("epoch")
	page, changed, ok := s.Events.Since(topic, epoch, after)
	if !ok {
		writeError(w, http.StatusBadRequest, "неизвестный журнал")
		return
	}
	if len(page.Events) == 0 && !page.Reset {
		wait := time.NewTimer(logWait)
		defer wait.Stop()
		for len(page.Events) == 0 && !page.Reset {
			select {
			case <-r.Context().Done():
				return
			case <-wait.C:
				writeJSON(w, http.StatusOK, page)
				return
			case <-changed:
			}
			// Events of other topics also wake the waiter; keep waiting for ours.
			page, changed, _ = s.Events.Since(topic, epoch, after)
		}
		batch := time.NewTimer(logBatch)
		defer batch.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-batch.C:
		}
		page, _, _ = s.Events.Since(topic, epoch, after)
	}
	writeJSON(w, http.StatusOK, page)
}

// unitReason returns the last line a failed unit invocation logged, so a
// crash shows why it happened. Called only for fresh failures. No priority
// filter: daemons commonly print errors to stderr, which journald stores as
// info. systemd's own messages carry INVOCATION_ID, not the trusted
// _SYSTEMD_INVOCATION_ID, and are not matched.
func (s *Server) unitReason(ctx context.Context, invocation string) string {
	if len(invocation) != 32 || strings.Trim(invocation, "0123456789abcdef") != "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 2 * time.Second}
	}
	out, err := runner.Run(ctx, "journalctl", "--no-pager", "--quiet", "-o", "cat", "-n", "1", "_SYSTEMD_INVOCATION_ID="+invocation)
	if err != nil {
		return ""
	}
	out = strings.TrimSpace(out)
	if len(out) > 300 {
		cut := 300
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut] + "…"
	}
	return out
}

func (s *Server) queryLog() bool {
	if s.Engine == nil {
		return false
	}
	cfg := s.Engine.Current()
	return cfg != nil && cfg.DNS.QueryLog
}

// followJournal is started once with the server.
func (s *Server) followJournal(ctx context.Context) {
	j := &eventlog.Journal{Log: s.Events, Reason: s.unitReason, DNS: s.queryLog, VPNServer: s.vpnServerName}
	j.Follow(ctx)
}

const dnsLogPath = "/var/log/netos/dns.log"

// tailDNSLog is the only reader of the resolver query file (dnsmasq,
// dnsproxy): it feeds the DNS topic and client history. It reads appended
// bytes every 2 s, only while the query log is enabled.
func (s *Server) tailDNSLog(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var tail runtime.DNSFileTail
	defer tail.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !s.queryLog() {
			tail.Close()
			continue
		}
		lines, err := tail.Read(dnsLogPath)
		if err != nil {
			continue
		}
		s.addDNSLines(time.Now(), lines)
	}
}

func (s *Server) addDNSLines(now time.Time, lines []string) {
	for _, line := range lines {
		if s.ClientHistory != nil {
			if addr, domain := runtime.ParseDNSQuery(line); addr != "" {
				s.ClientHistory.AddDNS(now, addr, domain)
			}
		}
		if client, text, ok := eventlog.DNSQuery(line); ok {
			s.Events.Add(now, eventlog.DNS, eventlog.Info, client, text)
		}
	}
}

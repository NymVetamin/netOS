package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/eventlog"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/store"
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
	}
	// A continuation must batch even when events were already pending. A
	// rotated list is still a continuation; only the first snapshot or a
	// different daemon epoch bypasses the delay.
	if epoch == page.Epoch && after > 0 {
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
	j := &eventlog.Journal{Log: s.Events, LAN: s.lan, Reason: s.unitReason, DNS: s.queryLog, VPNServer: s.vpnServerName}
	j.Follow(ctx)
}

const dnsLogPath = "/var/log/netos/dns.log"

// tailDNSLog is the only reader of the resolver query file (dnsmasq,
// dnsproxy): it feeds the DNS topic and client history. It reads appended
// bytes every 2 s, only while the query log is enabled.
func (s *Server) tailDNSLog(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	tail := &s.DNSLogTail
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
		} else if s.lan != nil {
			// While the query log is on, dnsmasq writes its DHCP lines here too.
			s.lan.DHCP(now, line)
		}
	}
}

// lanNames resolves MAC addresses and hostapd interfaces against the applied
// configuration. Called per Wi-Fi/DHCP event: O(clients) or O(radios + SSIDs).
func (s *Server) lanNames() *eventlog.Names {
	current := func() *config.Config {
		if s.Engine == nil {
			return nil
		}
		return s.Engine.Current()
	}
	return &eventlog.Names{
		Client: func(mac string) string {
			if cfg := current(); cfg != nil {
				for _, c := range cfg.Clients {
					if strings.EqualFold(c.MAC, mac) {
						return c.Name
					}
				}
			}
			return ""
		},
		SSID: func(iface string) string {
			cfg := current()
			if cfg == nil {
				return ""
			}
			for _, radio := range cfg.WiFi {
				index := 0
				if iface != radio.Device {
					suffix, matches := strings.CutPrefix(iface, radio.Device+"-n")
					if !matches {
						continue
					}
					n, err := strconv.Atoi(suffix)
					if err != nil || n < 1 || strconv.Itoa(n) != suffix {
						continue
					}
					index = n
				}
				// RenderRadio numbers only enabled SSIDs: the primary is 0,
				// and the first additional BSS has suffix -n1.
				for _, ssid := range radio.SSIDs {
					if !ssid.Enabled {
						continue
					}
					if index == 0 {
						return ssid.SSID
					}
					index--
				}
			}
			return ""
		},
	}
}

// UseEvents shares an event log created before the panel, so monitors started
// earlier report into the same log. Call before Start.
func (s *Server) UseEvents(l *eventlog.Log) {
	s.Events, s.lan.Log = l, l
}

// watchedLink limits cable events to physical ports of the configuration:
// tunnels, bridges and veths change state as a consequence, not a cause.
func (s *Server) watchedLink(name string) bool {
	if s.Engine == nil || s.Engine.Current() == nil {
		return false
	}
	for _, i := range s.Engine.Current().Interfaces {
		if i.Name == name && (i.Type == "physical" || i.Type == "") {
			return true
		}
	}
	return false
}

var auditActions = map[string]string{
	"apply":           "применение конфигурации",
	"confirm":         "подтверждение применения",
	"rollback":        "откат конфигурации",
	"restore":         "восстановление из копии",
	"update":          "обновление netOS",
	"backup-delete":   "удаление резервной копии",
	"client-wake":     "включение устройства по сети",
	"panel-restart":   "перезапуск netOS",
	"password_change": "смена пароля",
}

var rollbackReasons = map[string]string{
	"timeout": "применение не подтверждено вовремя",
	"health":  "не прошла проверка после применения",
	"manual":  "по команде администратора",
}

// auditEvent turns an audit entry (the persistent record of panel and CLI
// actions) into a log event: logins go to Access, the rest to System.
func auditEvent(e store.AuditEntry) (topic, level, source, msg string) {
	source = e.User
	if source == "" {
		source = "система"
	}
	from := ""
	if e.SourceIP != "" {
		from = " с " + e.SourceIP
	}
	if e.Action == "login" {
		if e.Success {
			return eventlog.Access, eventlog.Info, "панель", "вход " + e.User + from
		}
		return eventlog.Access, eventlog.Warning, "панель", "неудачный вход " + e.User + from
	}
	msg = auditActions[e.Action]
	if msg == "" {
		msg = e.Action
	}
	if e.Target != "" {
		if e.Action == "apply" || e.Action == "confirm" || e.Action == "rollback" {
			msg += ", ревизия " + e.Target
		} else {
			msg += ": " + e.Target
		}
	}
	level = eventlog.Info
	if e.Action == "rollback" {
		// main records "reason: details" for every rollback of the engine.
		reason, details, _ := strings.Cut(e.Detail, ": ")
		if text := rollbackReasons[reason]; text != "" {
			reason = text
		}
		if details = strings.TrimSpace(details); details != "" {
			reason += ": " + details
		}
		if reason != "" {
			msg += " — " + reason
		}
		return eventlog.System, eventlog.Warning, source, msg
	}
	if !e.Success {
		level = eventlog.Error
		msg += " — не удалось"
		if e.Detail != "" {
			msg += ": " + e.Detail
		}
	}
	return eventlog.System, level, source, msg + from
}

func (s *Server) addAudit(e store.AuditEntry) {
	topic, level, source, msg := auditEvent(e)
	s.Events.Add(e.At, topic, level, source, msg)
}

// refillAudit shows the newest audit entries after a restart; they are kept
// in SQLite anyway, so System and panel logins survive restarts. One query.
func (s *Server) refillAudit() {
	if s.Store == nil {
		return
	}
	entries, err := s.Store.ListAudit(eventlog.Size)
	if err != nil || len(entries) == 0 {
		return
	}
	history := eventlog.New()
	for i := len(entries) - 1; i >= 0; i-- {
		topic, level, source, msg := auditEvent(entries[i])
		history.Add(entries[i].At, topic, level, source, msg)
	}
	s.Events.MergeHistory(history)
}

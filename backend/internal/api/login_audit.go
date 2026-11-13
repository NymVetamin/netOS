package api

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

const earlyLoginLimit = 20
const panelLoginMarker = "netos-panel-access-v1 "

// Fast unauthenticated failures must not turn into an unbounded disk writer.
// One process-wide window needs no source map, cleanup timer or background job.
type earlyLoginAudit struct {
	mu    sync.Mutex
	start time.Time
	count int
}

func (a *earlyLoginAudit) take(now time.Time) (detail, notice bool, until time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Concurrent callers can capture their timestamps before acquiring this
	// lock in a different order. An older timestamp must not reopen the budget.
	if a.start.IsZero() || now.Sub(a.start) >= time.Minute {
		a.start, a.count = now, 0
	}
	until = a.start.Add(time.Minute)
	if a.count > earlyLoginLimit {
		return false, false, until
	}
	a.count++
	return a.count <= earlyLoginLimit, a.count == earlyLoginLimit+1, until
}

type panelLoginRecord struct {
	Reason  string `json:"reason"`
	User    string `json:"user,omitempty"`
	Address string `json:"address,omitempty"`
	Until   string `json:"until,omitempty"`
}

func (s *Server) logEarlyLogin(reason, user, address string) {
	if s.Logger == nil {
		return
	}
	detail, notice, until := s.loginAudit.take(time.Now())
	if !detail && !notice {
		return
	}
	if len(user) > 64 {
		user = ""
	}
	if len(address) > 128 {
		address = ""
	}
	record := panelLoginRecord{Reason: reason, User: user, Address: address}
	if notice {
		// This concerns all sources, not the peer that exhausted the budget.
		record = panelLoginRecord{Reason: "limited", Until: until.UTC().Format(time.RFC3339Nano)}
	}
	raw, _ := json.Marshal(record) // strings only; never includes a body or password
	s.Logger.Infof("%s%s", panelLoginMarker, raw)
}

func panelJournalFields(entry *logEntry) bool {
	if entry.Unit != "netosd.service" || len(entry.Message) > 2048 || !strings.Contains(entry.Message, panelLoginMarker) {
		return false
	}
	message := entry.Message
	// stdLogger uses Go's default date/time prefix, then a fixed level marker.
	if len(message) >= 20 && message[19] == ' ' {
		if _, err := time.Parse("2006/01/02 15:04:05", message[:19]); err == nil {
			message = message[20:]
		}
	}
	prefix := "[инфо] " + panelLoginMarker
	if !strings.HasPrefix(message, prefix) {
		return false
	}
	var record panelLoginRecord
	if json.Unmarshal([]byte(message[len(prefix):]), &record) != nil || len(record.User) > 64 || len(record.Address) > 128 {
		return false
	}
	event := ""
	switch record.Reason {
	case "request":
		event = "Некорректный запрос входа в панель"
	case "credentials":
		event = "Недопустимый формат учётных данных панели"
	case "blocked":
		event = "Вход в панель временно ограничен после неудачных попыток"
	case "busy":
		event = "Вход в панель отклонён: проверка паролей занята"
	case "limited":
		if _, err := time.Parse(time.RFC3339Nano, record.Until); err != nil || record.User != "" || record.Address != "" {
			return false
		}
		event = "Достигнут лимит подробных записей ранних отказов входа; остальные до " + record.Until + " не сохраняются"
	default:
		return false
	}
	if record.Reason != "limited" && record.Until != "" {
		return false
	}
	entry.Event, entry.Protocol, entry.Result = event, "panel", "failure"
	entry.User, entry.Address = record.User, record.Address
	if record.Reason == "limited" {
		entry.Result, entry.Severity = "info", "warning"
	}
	return true
}

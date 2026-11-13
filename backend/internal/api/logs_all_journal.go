package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

// Each journal stream keeps its own snapshot even when another source fills
// the page before any of its records are consumed.
type allJournalPosition struct {
	Anchor string `json:"anchor,omitempty"`
	Upper  string `json:"upper,omitempty"`
	Lower  string `json:"lower,omitempty"`
	Done   bool   `json:"done,omitempty"`
}

func (p allJournalPosition) valid() bool {
	if strings.ContainsAny(p.Anchor+p.Upper+p.Lower, "\r\n\x00") || (p.Anchor != "" && p.Upper != "") {
		return false
	}
	if p.Done {
		return p.Anchor == "" && p.Upper == "" && p.Lower == ""
	}
	return p.Lower != "" && (p.Anchor != "" || p.Upper != "")
}

func readAllJournalBatch(ctx context.Context, runner system.Runner, c journalLogCursor, pos *allJournalPosition, kernel bool) ([]logCandidate, bool, error) {
	if pos.Done {
		return nil, false, nil
	}
	base := []string{"--no-pager", "--quiet", "-o", "json", "--until=" + journalPageTime(c.To)}
	if kernel {
		base = append(base, "_TRANSPORT=kernel")
	} else {
		base = append(base, "-u", "netos*.service", "-u", "dnsmasq.service", "-u", "ssh.service", "-u", "sshd.service")
	}
	if pos.Lower == "" {
		raw, err := runner.Run(ctx, "journalctl", append(base, "--since="+journalPageTime(c.From), "--output-fields=__CURSOR,__REALTIME_TIMESTAMP", "-n", "+1")...)
		if err != nil {
			return nil, false, err
		}
		first, _, err := journalCandidateBatch(raw, "", false, "общего журнала")
		if err != nil {
			return nil, false, err
		}
		if len(first) > 1 {
			return nil, false, fmt.Errorf("несколько нижних границ периода")
		}
		if len(first) == 0 {
			pos.Done = true
			return nil, false, nil
		}
		pos.Lower = first[0].id
	}
	anchor := pos.Anchor
	if anchor == "" {
		anchor = pos.Upper
	}
	limit := logScanSize + 1
	if pos.Anchor != "" {
		limit++
	}
	args := append(base, "--reverse", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_TRANSPORT,_PID,UNIT,MESSAGE_ID,PRIORITY,IKE_SA_NAME", "-n", strconv.Itoa(limit))
	if anchor == "" {
		args = append(args, "--since="+journalPageTime(c.From))
	} else {
		args = append(args, "--cursor="+anchor)
	}
	raw, err := runner.Run(ctx, "journalctl", args...)
	if err != nil {
		return nil, false, err
	}
	rows, stale, err := journalCandidateBatch(raw, anchor, pos.Anchor != "", "общего журнала")
	if err == nil && !stale && anchor == "" && len(rows) > 0 {
		pos.Upper = rows[0].id
	}
	return rows, stale, err
}

// Classify a journal record once. Specific protocol events take precedence
// over the generic service warning, while messages from unrelated units are
// never interpreted as SSH, DNS, or managed service events.
func allJournalEntry(row map[string]json.RawMessage, kernel bool) (logEntry, bool) {
	field := func(key string) string { var value string; _ = json.Unmarshal(row[key], &value); return value }
	if field("_TRANSPORT") == "kernel" {
		if kernel {
			return journalLogEntry(row, "firewall")
		}
		return logEntry{}, false
	}
	if kernel {
		return logEntry{}, false
	}
	return journalLogEntry(row, "all")
}

// Reuse the decoded message, timestamp and unit; trying complete source
// decoders in succession would parse the same timestamp for every attempt.
func classifyAllUnitEntry(entry logEntry, field func(string) string) (logEntry, bool) {
	unit := field("_SYSTEMD_UNIT")
	if xrayLogFields(&entry, unit) {
		entry.Source = "vpn"
		return entry, true
	}
	if unit == "netosd.service" && panelJournalFields(&entry) {
		entry.Source = "access"
		return entry, true
	}
	if unit == "ssh.service" || unit == "sshd.service" {
		entry.Source = "access"
		keep := sshLogFields(&entry)
		if !keep {
			return logEntry{}, false
		}
		return entry, keep
	}
	if unit == "dnsmasq.service" || unit == "netos-dnsmasq.service" || unit == "netos-unbound.service" || unit == "netos-dnsproxy.service" {
		if isDNSQuery(entry.Message) {
			entry.Source = "dns"
			return entry, true
		}
	}
	keep := false
	if unit == "netos-strongswan.service" {
		keep = ikeLogFields(&entry, field)
	} else {
		keep = vpnLogFields(&entry) || l2tpLogFields(&entry)
	}
	if keep {
		entry.Source = "vpn"
		return entry, true
	}
	if field("_PID") == "1" && field("UNIT") != "" {
		unit = field("UNIT")
	}
	if strings.HasPrefix(unit, "netos") && strings.HasSuffix(unit, ".service") {
		entry.Source = "services"
		entry.Unit, entry.Event, entry.Severity, keep = serviceLogFields(field, entry.Message)
		if keep {
			return entry, true
		}
	}
	return logEntry{}, false
}

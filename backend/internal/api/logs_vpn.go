package api

import (
	"net"
	"regexp"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// Historical identity comes from the event, never today's reused srv index.
func vpnUnitEventIdentity(e *logEntry, field func(string) string) {
	if (e.Protocol != "openconnect" && e.Protocol != "l2tp") || field("_SYSTEMD_UNIT") != e.Unit {
		return
	}
	if id := field("NETOS_VPN_SERVER_ID"); config.SafeObjectID(id) {
		e.Server = id + " (" + e.Server + ")"
	}
}

// Filter before journalctl's limit: routine daemon output must not evict events.
const ocservEventPattern = `user logged in|user disconnected|failed authentication|failed cookie authentication attempt`

var ocservLogUnit = regexp.MustCompile(`^netos-ocserv-srv([0-9]+)\.service$`)
var ocservLogPeer = regexp.MustCompile(`^(main|worker)(?:\[([^\]]*)\])?:\s*(\S+)`)
var ocservFailedUser = regexp.MustCompile(`failed authentication for '([^']*)'`)
var ocservSessionEvent = regexp.MustCompile(`^main(?:\[[^\]]*\])?:\s*\S+ (user logged in|user disconnected)(?: \(|$)`)
var ocservAuthEvent = regexp.MustCompile(`^worker(?:\[[^\]]*\])?:\s*\S+ (?:[a-zA-Z0-9_-]+\.c:[0-9]+: )?failed (?:authentication for '[^']*'|cookie authentication attempt)$`)
var ocservEventMatch = regexp.MustCompile(ocservEventPattern)

func vpnLogFields(e *logEntry) bool {
	unit := ocservLogUnit.FindStringSubmatch(e.Unit)
	if unit == nil {
		return false
	}
	// These are daemon events, not observations of traffic or current status.
	if event := ocservSessionEvent.FindStringSubmatch(e.Message); event != nil {
		if event[1] == "user logged in" {
			e.Event, e.Result = "Вход в VPN", "success"
		} else {
			e.Event, e.Result = "VPN-соединение завершено", "info"
		}
	} else if ocservAuthEvent.MatchString(e.Message) {
		e.Event, e.Result = "Отказ во входе VPN", "failure"
	} else if ocservEventMatch.MatchString(e.Message) {
		// Keep unfamiliar daemon versions readable without guessing an outcome.
		e.Event, e.Result = "Событие OpenConnect", "info"
	} else {
		return false
	}
	e.Protocol, e.Server = "openconnect", "srv"+unit[1]
	if peer := ocservLogPeer.FindStringSubmatch(e.Message); peer != nil {
		e.User = peer[2]
		address := peer[3]
		if peer[1] == "main" {
			// main logs the remote port; worker logs just the address.
			if host, _, err := net.SplitHostPort(address); err == nil {
				address = host
			} else if i := strings.LastIndexByte(address, ':'); i >= 0 {
				address = address[:i]
			}
		}
		if net.ParseIP(address) != nil {
			e.Address = address
		}
	}
	if e.User == "" {
		if user := ocservFailedUser.FindStringSubmatch(e.Message); user != nil {
			e.User = user[1]
		}
	}
	return true
}

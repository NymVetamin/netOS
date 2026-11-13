package api

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/xraylog"
)

var xrayLogUnit = regexp.MustCompile(`^netos-xray-srv([0-9]+)\.service$`)
var xrayLogEnvelope = regexp.MustCompile(`^(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)? )?from (\S+) (accepted|rejected) (.*)$`)
var xrayAcceptedDetail = regexp.MustCompile(`^(?:tcp|udp):\S+ \[[^\[\]\r\n]+\](?: email: (\S+))?$`)

// Caller supplies a trusted _SYSTEMD_UNIT, never SYSLOG_IDENTIFIER.
// Acceptance is a proxy request, not proof that its destination was reached.
func xrayLogFields(e *logEntry, unit string) bool {
	u := xrayLogUnit.FindStringSubmatch(unit)
	if u == nil {
		return false
	}
	if loss, ok := xraylog.ParseLoss(e.Message); ok {
		e.Unit, e.Protocol, e.Server = unit, "xray", "srv"+u[1]
		e.Event = "Часть записей Xray не сохранена: " + strconv.FormatUint(loss.Count, 10)
		e.Result, e.Severity = "warning", "warning"
		return true
	}
	m := xrayLogEnvelope.FindStringSubmatch(e.Message)
	if m == nil {
		return false
	}
	source := m[1]
	if strings.HasPrefix(source, "tcp:") || strings.HasPrefix(source, "udp:") {
		source = source[4:]
	}
	host, port, err := net.SplitHostPort(source)
	if err != nil || net.ParseIP(host) == nil || port == "" {
		return false
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return false
	}
	user := ""
	if m[2] == "accepted" {
		detail := xrayAcceptedDetail.FindStringSubmatch(m[3])
		if detail == nil {
			return false
		}
		user = detail[1]
		e.Event, e.Result = "Принято соединение Xray", "success"
	} else {
		e.Event, e.Result = "Отказ в соединении Xray", "failure"
		// Rejected VLESS requests can include the presented authentication UUID.
		// Unknown rejection formats must not expose arbitrary credentials either.
		reason := strings.TrimSpace(m[3])
		switch {
		case reason == "proxy/socks: invalid username or password":
		case strings.HasPrefix(reason, "proxy/vless/encoding: invalid request user id:"):
			reason = "proxy/vless/encoding: invalid request user id: [скрыто]"
		default:
			reason = "[подробности отказа скрыты: формат может содержать учётные данные]"
		}
		end := len(e.Message) - len(m[3])
		e.Message = e.Message[:end] + reason
	}
	e.Unit, e.Protocol, e.Server, e.User, e.Address = unit, "xray", "srv"+u[1], user, host
	return true
}

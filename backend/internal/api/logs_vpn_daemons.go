package api

import (
	"net"
	"regexp"
)

const ikeEventPattern = `^RADIUS authentication of |^IKE_SA netos-srv[0-9]+\[[0-9]+\] established between |^deleting IKE_SA netos-srv[0-9]+\[`
const l2tpEventPattern = `^Peer .* (authenticated with |failed CHAP authentication$)|^xl2tpd\[[0-9]+\]: Connection (established to |[0-9]+ closed to )`

var ikeServerName = regexp.MustCompile(`^netos-srv([0-9]+)$`)
var ikeAuthEvent = regexp.MustCompile(`^RADIUS authentication of '(.*)' (successful|failed)$`)
var ikeConnectionEvent = regexp.MustCompile(`^(IKE_SA|deleting IKE_SA) (netos-srv[0-9]+)\[[0-9]+\] (?:established )?between [^\s\[]+\[[^\]]*\]\.\.\.([^\s\[]+)\[.*\]$`)
var ikeEventMatch = regexp.MustCompile(ikeEventPattern)
var l2tpLogUnit = regexp.MustCompile(`^netos-vpn-l2tp-srv([0-9]+)\.service$`)
var l2tpPeerAuth = regexp.MustCompile(`^Peer (.+) authenticated with (?:CHAP|PAP)$`)
var l2tpPeerRefused = regexp.MustCompile(`^Peer (.+) failed CHAP authentication$`)
var l2tpConnectionEvent = regexp.MustCompile(`^xl2tpd\[[0-9]+\]: Connection (established to|[0-9]+ closed to) ([^, ]+),`)
var l2tpEventMatch = regexp.MustCompile(l2tpEventPattern)

func ikeLogFields(e *logEntry, field func(string) string) bool {
	server := ikeServerName.FindStringSubmatch(field("IKE_SA_NAME"))
	if server == nil || !ikeEventMatch.MatchString(e.Message) {
		return false
	}
	e.Protocol, e.Server = "ikev2", "srv"+server[1]
	e.Event, e.Result = "Событие IKEv2", "info"
	if auth := ikeAuthEvent.FindStringSubmatch(e.Message); auth != nil {
		e.User = auth[1]
		if auth[2] == "successful" {
			e.Event, e.Result = "Пользователь VPN прошёл аутентификацию", "success"
		} else {
			e.Event, e.Result = "Отказ в аутентификации VPN", "failure"
		}
	} else if connection := ikeConnectionEvent.FindStringSubmatch(e.Message); connection != nil && connection[2] == field("IKE_SA_NAME") {
		if connection[1] == "IKE_SA" {
			e.Event, e.Result = "Защищённое соединение IKEv2 установлено", "success"
		} else {
			// Deletion starts teardown; it is not proof that every resource is gone.
			e.Event = "Завершение соединения IKEv2"
		}
		if net.ParseIP(connection[3]) != nil {
			e.Address = connection[3]
		}
		// The peer's IKE identity is not necessarily the authenticated EAP user.
	}
	return true
}

func l2tpLogFields(e *logEntry) bool {
	server := l2tpLogUnit.FindStringSubmatch(e.Unit)
	if server == nil || !l2tpEventMatch.MatchString(e.Message) {
		return false
	}
	e.Protocol, e.Server = "l2tp", "srv"+server[1]
	e.Event, e.Result = "Событие L2TP", "info"
	if auth := l2tpPeerAuth.FindStringSubmatch(e.Message); auth != nil {
		e.Event, e.Result, e.User = "Пользователь VPN прошёл аутентификацию", "success", auth[1]
	} else if refused := l2tpPeerRefused.FindStringSubmatch(e.Message); refused != nil {
		e.Event, e.Result, e.User = "Отказ в аутентификации VPN", "failure", refused[1]
	} else if connection := l2tpConnectionEvent.FindStringSubmatch(e.Message); connection != nil {
		if connection[1] == "established to" {
			// The transport exists before PPP authenticates the user.
			e.Event = "Установлено соединение L2TP до аутентификации"
		} else {
			e.Event = "Соединение L2TP закрыто"
		}
		if net.ParseIP(connection[2]) != nil {
			e.Address = connection[2]
		}
	}
	return true
}

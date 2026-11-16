package eventlog

import (
	"regexp"
	"strconv"
)

var vpnTypeNames = map[string]string{"ocserv": "OpenConnect", "ikev2": "IKEv2", "l2tp": "L2TP"}

// Formats checked live on Debian 13 (16.11.2026): ocserv 1.3.0, charon-systemd
// with eap-radius and FreeRADIUS, pppd under xl2tpd 1.3.18. ocserv reports a
// refusal only once the client has used up its password attempts; a client
// that gives up after one wrong password leaves no line to show.
var (
	ocservUnit    = regexp.MustCompile(`^netos-ocserv-srv([0-9]+)\.service$`)
	ocservRefused = regexp.MustCompile(`^worker(?:\[[^\]]*\])?:\s*(\S+) (?:[a-zA-Z0-9_-]+\.c:[0-9]+: )?failed authentication for '([^']*)'$`)
	ikeServer     = regexp.MustCompile(`^netos-srv([0-9]+)$`)
	ikeRefused    = regexp.MustCompile(`^RADIUS authentication of '(.*)' failed$`)
	l2tpUnit      = regexp.MustCompile(`^netos-vpn-l2tp-srv([0-9]+)\.service$`)
	l2tpRefused   = regexp.MustCompile(`^Peer (.+) failed CHAP authentication$`)
)

// VPNRefusal recognizes a refused login of a netOS VPN server. Successful
// logins and disconnects come from the session monitor, not from here.
func VPNRefusal(rec journalRecord) (typ string, index int, text string, ok bool) {
	msg := rec["MESSAGE"]
	if u := ocservUnit.FindStringSubmatch(rec["_SYSTEMD_UNIT"]); u != nil {
		if m := ocservRefused.FindStringSubmatch(msg); m != nil {
			index, _ = strconv.Atoi(u[1])
			return "ocserv", index, "неудачный вход " + m[2] + " с " + m[1], true
		}
	}
	if u := ikeServer.FindStringSubmatch(rec["IKE_SA_NAME"]); u != nil {
		if m := ikeRefused.FindStringSubmatch(msg); m != nil {
			index, _ = strconv.Atoi(u[1])
			return "ikev2", index, "неудачный вход " + m[1] + ": неверный логин или пароль", true
		}
	}
	if u := l2tpUnit.FindStringSubmatch(rec["_SYSTEMD_UNIT"]); u != nil {
		if m := l2tpRefused.FindStringSubmatch(msg); m != nil {
			index, _ = strconv.Atoi(u[1])
			return "l2tp", index, "неудачный вход " + m[1] + ": неверный логин или пароль", true
		}
	}
	return "", 0, "", false
}

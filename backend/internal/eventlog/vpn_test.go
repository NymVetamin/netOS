package eventlog

import (
	"strings"
	"testing"
	"time"
)

func TestVPNRefusals(t *testing.T) {
	l := New()
	names := map[string]string{"ocserv/1": "Офис", "l2tp/2": "Склад"}
	j := &Journal{Log: l, VPNServer: func(typ string, index int) string {
		return names[typ+"/"+string(rune('0'+index))]
	}}
	feed(j, time.Now(),
		`{"__CURSOR":"1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"ocserv","_SYSTEMD_UNIT":"netos-ocserv-srv1.service","MESSAGE":"worker[bob]: 203.0.113.5 worker-auth.c:1234: failed authentication for 'bob'"}`,
		`{"__CURSOR":"2","__REALTIME_TIMESTAMP":"2","SYSLOG_IDENTIFIER":"ocserv","_SYSTEMD_UNIT":"netos-ocserv-srv1.service","MESSAGE":"main[bob]:203.0.113.5:443 user logged in"}`,
		`{"__CURSOR":"3","__REALTIME_TIMESTAMP":"3","SYSLOG_IDENTIFIER":"charon-systemd","IKE_SA_NAME":"netos-srv3","MESSAGE":"RADIUS authentication of 'alice' failed"}`,
		`{"__CURSOR":"4","__REALTIME_TIMESTAMP":"4","SYSLOG_IDENTIFIER":"charon-systemd","IKE_SA_NAME":"netos-srv3","MESSAGE":"RADIUS authentication of 'alice' successful"}`,
		`{"__CURSOR":"5","__REALTIME_TIMESTAMP":"5","SYSLOG_IDENTIFIER":"pppd","_SYSTEMD_UNIT":"netos-vpn-l2tp-srv2.service","MESSAGE":"Peer carol failed CHAP authentication"}`,
		// PPPoE uplink pppd is not a netOS VPN server.
		`{"__CURSOR":"6","__REALTIME_TIMESTAMP":"6","SYSLOG_IDENTIFIER":"pppd","_SYSTEMD_UNIT":"netos-pppoe-wan1.service","MESSAGE":"Peer x failed CHAP authentication"}`,
	)
	want := "warning Офис: неудачный вход bob с 203.0.113.5\nwarning IKEv2: неудачный вход alice: неверный логин или пароль\nwarning Склад: неудачный вход carol: неверный логин или пароль"
	if got := strings.Join(messages(l, VPN), "\n"); got != want {
		t.Fatal(got)
	}
}

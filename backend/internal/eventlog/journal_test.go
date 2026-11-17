package eventlog

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Records follow systemd's catalog fields; MESSAGE texts are as systemd 252
// (Debian 12) prints them.
func unitRecord(cursor, id, unit string, extra string) string {
	return `{"__CURSOR":"` + cursor + `","__REALTIME_TIMESTAMP":"1792000000000000","_PID":"1","MESSAGE_ID":"` + id + `","UNIT":"` + unit + `","MESSAGE":"x"` + extra + `}`
}

func messages(l *Log, topic string) []string {
	p, _, _ := l.Since(topic, "", 0)
	out := []string{}
	for i := len(p.Events) - 1; i >= 0; i-- {
		e := p.Events[i]
		out = append(out, e.Level+" "+e.Source+": "+e.Message)
	}
	return out
}

func feed(j *Journal, now time.Time, lines ...string) {
	for _, line := range lines {
		j.Handle(context.Background(), []byte(line), now)
	}
}

func TestServiceLifecycleIsOneEventPerFact(t *testing.T) {
	l := New()
	reasons := 0
	j := &Journal{Log: l, Reason: func(_ context.Context, id string) string {
		reasons++
		if id != "0123456789abcdef0123456789abcdef" {
			t.Fatal(id)
		}
		return "bind: address in use"
	}}
	unit := "netos-dnsmasq.service"
	fresh := time.UnixMicro(1792000000000000).Add(5 * time.Second)
	feed(j, fresh,
		unitRecord("1", msgStarted, unit, `,"JOB_TYPE":"start","JOB_RESULT":"done"`),
		// crash with Restart=always: exit, failed, (restart scheduled is not
		// selected), stop of the restart job, start of the restart job.
		unitRecord("2", msgExit, unit, `,"EXIT_CODE":"exited","EXIT_STATUS":"2"`),
		unitRecord("3", msgFailed, unit, `,"UNIT_RESULT":"exit-code","INVOCATION_ID":"0123456789abcdef0123456789abcdef"`),
		unitRecord("4", msgStopped, unit, `,"JOB_TYPE":"restart","JOB_RESULT":"done"`),
		unitRecord("5", msgStarted, unit, `,"JOB_TYPE":"start","JOB_RESULT":"done"`),
		// administrator restart
		unitRecord("6", msgStopped, unit, `,"JOB_TYPE":"restart","JOB_RESULT":"done"`),
		unitRecord("7", msgStarted, unit, `,"JOB_TYPE":"start","JOB_RESULT":"done"`),
		// failure without restart: failed + failed start job
		unitRecord("8", msgExit, unit, `,"EXIT_CODE":"killed","EXIT_STATUS":"SEGV"`),
		unitRecord("9", msgFailed, unit, `,"UNIT_RESULT":"signal"`),
		unitRecord("10", msgJobFailed, unit, `,"JOB_TYPE":"start","JOB_RESULT":"failed"`),
		unitRecord("11", msgStarted, unit, `,"JOB_TYPE":"start"`),
		unitRecord("12", msgStopped, unit, `,"JOB_TYPE":"stop"`),
		// systemd 257 start limit: restart scheduled, then the unit fails
		// again with the old result and no process exit, then the job fails.
		unitRecord("12a", msgStarted, "netos-qa.service", `,"JOB_TYPE":"start"`),
		unitRecord("12b", msgExit, "netos-qa.service", `,"EXIT_CODE":"exited","EXIT_STATUS":"3"`),
		unitRecord("12c", msgFailed, "netos-qa.service", `,"UNIT_RESULT":"exit-code"`),
		unitRecord("12d", msgFailed, "netos-qa.service", `,"UNIT_RESULT":"exit-code"`),
		unitRecord("12e", msgJobFailed, "netos-qa.service", `,"JOB_TYPE":"start","JOB_RESULT":"failed"`),
		// dependency failure reports only a failed job
		unitRecord("13", msgJobFailed, "netos-kea-dhcp4.service", `,"JOB_RESULT":"dependency"`),
		// foreign units are not shown
		unitRecord("14", msgStarted, "apt-daily.service", ``),
	)
	want := []string{
		"info netos-dnsmasq: запущена",
		"error netos-dnsmasq: сбой: процесс завершился с ошибкой (код 2): bind: address in use",
		"info netos-dnsmasq: снова запущена после сбоя",
		"info netos-dnsmasq: перезапущена",
		"error netos-dnsmasq: сбой: процесс убит сигналом (сигнал SEGV)",
		"info netos-dnsmasq: снова запущена после сбоя",
		"info netos-dnsmasq: остановлена",
		"info netos-qa: запущена",
		"error netos-qa: сбой: процесс завершился с ошибкой (код 3)",
		"error netos-qa: перезапуски прекращены: слишком частые сбои",
		"error netos-kea-dhcp4: не запустилась: не запустилась зависимость",
	}
	if got := messages(l, Services); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s", strings.Join(got, "\n"))
	}
	if reasons != 1 || len(j.units) != 2 || j.cursor != "14" {
		t.Fatal(reasons, j.units, j.cursor)
	}
}

func TestStartupRefillDoesNotRunCommands(t *testing.T) {
	j := &Journal{Log: New(), Reason: func(context.Context, string) string { t.Fatal("command during refill"); return "" }}
	old := time.UnixMicro(1792000000000000).Add(time.Hour)
	feed(j, old, unitRecord("1", msgFailed, "netos-x.service", `,"UNIT_RESULT":"exit-code","INVOCATION_ID":"0123456789abcdef0123456789abcdef"`))
	if got := messages(j.Log, Services); len(got) != 1 {
		t.Fatal(got)
	}
}

func TestFirewallAndSSHEvents(t *testing.T) {
	l := New()
	j := &Journal{Log: l}
	feed(j, time.Now(),
		`{"__CURSOR":"a","__REALTIME_TIMESTAMP":"1","_TRANSPORT":"kernel","MESSAGE":"netos drop-ssh: IN=eth0 OUT= MAC=00:11 SRC=203.0.113.5 DST=192.0.2.1 LEN=60 TOS=0x00 PROTO=TCP SPT=51515 DPT=22 WINDOW=64240 SYN"}`,
		`{"__CURSOR":"b","__REALTIME_TIMESTAMP":"2","_TRANSPORT":"kernel","MESSAGE":"netos ping: IN=br0 OUT=eth1 SRC=2001:db8::1 DST=2001:db8::2 LEN=64 PROTO=ICMPv6 TYPE=128 CODE=0"}`,
		`{"__CURSOR":"c","__REALTIME_TIMESTAMP":"3","_TRANSPORT":"kernel","MESSAGE":"e1000e: eth0 NIC Link is Up 1000 Mbps Full Duplex"}`,
		`{"__CURSOR":"d","__REALTIME_TIMESTAMP":"4","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for root from 198.51.100.7 port 50022 ssh2: ED25519 SHA256:x"}`,
		`{"__CURSOR":"e","__REALTIME_TIMESTAMP":"5","SYSLOG_IDENTIFIER":"sshd-session","MESSAGE":"Invalid user bob from 198.51.100.8 port 4444"}`,
		`{"__CURSOR":"f","__REALTIME_TIMESTAMP":"6","SYSLOG_IDENTIFIER":"sshd-session","MESSAGE":"Failed password for invalid user bob from 198.51.100.8 port 4444 ssh2"}`,
		`{"__CURSOR":"f2","__REALTIME_TIMESTAMP":"6","SYSLOG_IDENTIFIER":"sshd-session","MESSAGE":"Invalid user scan from 198.51.100.10 port 4446"}`,
		`{"__CURSOR":"f3","__REALTIME_TIMESTAMP":"6","SYSLOG_IDENTIFIER":"sshd-session","MESSAGE":"Connection closed by invalid user scan 198.51.100.10 port 4446 [preauth]"}`,
		`{"__CURSOR":"g","__REALTIME_TIMESTAMP":"7","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 198.51.100.9 port 4445 ssh2"}`,
		`{"__CURSOR":"h","__REALTIME_TIMESTAMP":"8","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Disconnected from user root 198.51.100.7 port 50022"}`,
		`{"__CURSOR":"i","__REALTIME_TIMESTAMP":"9","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"pam_unix(sshd:session): session closed for user root"}`,
		`not json`,
		`{"__REALTIME_TIMESTAMP":"10","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for a from b port 1 ssh2"}`,
		`{"__CURSOR":"j","__REALTIME_TIMESTAMP":"11","SYSLOG_IDENTIFIER":"sshd","MESSAGE":[208,159]}`,
	)
	if got := strings.Join(messages(l, Firewall), "\n"); got != "info drop-ssh: TCP 203.0.113.5:51515 → 192.0.2.1:22, вход eth0\ninfo ping: ICMPv6 [2001:db8::1] → [2001:db8::2] тип 128, вход br0, выход eth1" {
		t.Fatal(got)
	}
	want := "info SSH: вход root с 198.51.100.7 (ключ)\nwarning SSH: неудачный вход bob с 198.51.100.8: нет такого пользователя\nwarning SSH: неудачный вход scan с 198.51.100.10: нет такого пользователя\nwarning SSH: неудачный вход root с 198.51.100.9: неверный пароль или ключ\ninfo SSH: выход root (198.51.100.7)"
	if got := strings.Join(messages(l, Access), "\n"); got != want {
		t.Fatal(got)
	}
	if j.cursor != "j" {
		t.Fatal(j.cursor)
	}
}

func TestSSHExistingUserNamedInvalid(t *testing.T) {
	log := New()
	j := &Journal{Log: log}
	lines := []string{
		`{"__CURSOR":"1","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for invalid from 198.51.100.7 port 4444 ssh2"}`,
		`{"__CURSOR":"2","__REALTIME_TIMESTAMP":"2","SYSLOG_IDENTIFIER":"sshd-session","MESSAGE":"Failed publickey for invalid from 2001:db8::7 port 4444 ssh2"}`,
		`{"__CURSOR":"3","__REALTIME_TIMESTAMP":"3","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for invalid from 198.51.100.7 port 4444 ssh2"}`,
	}
	for _, line := range lines {
		j.Handle(context.Background(), []byte(line), time.Time{})
	}
	got, _, _ := log.Since(Access, "", 0)
	if len(got.Events) != 3 {
		t.Fatalf("failed logins for existing invalid account: got %d events, want 3", len(got.Events))
	}
	for _, e := range got.Events {
		if e.Level != Warning || !strings.Contains(e.Message, "неудачный вход invalid с ") {
			t.Fatalf("wrong failed-login event: %+v", e)
		}
	}
}

// The user name is sent by an unauthenticated client and may hold spaces; the
// address sshd itself appended must be the one shown.
func TestSSHInvalidUserCannotForgeAddress(t *testing.T) {
	for line, want := range map[string]string{
		"Invalid user root from 10.0.0.5 from 203.0.113.9 port 40022":        "неудачный вход root from 10.0.0.5 с 203.0.113.9: нет такого пользователя",
		"Invalid user a from 10.0.0.5 port 1 from 203.0.113.9 port 40022":    "неудачный вход a from 10.0.0.5 port 1 с 203.0.113.9: нет такого пользователя",
		"Invalid user bob from 2001:db8::7 port 4444":                        "неудачный вход bob с 2001:db8::7: нет такого пользователя",
		"Invalid user bob from 198.51.100.8":                                 "неудачный вход bob с 198.51.100.8: нет такого пользователя",
		"Invalid user  from 198.51.100.8 port 4444":                          "",
		"Invalid user bob from":                                              "",
		"Failed password for invalid user root from 10.0.0.5 from 203.0.113": "",
	} {
		level, got, ok := SSHEvent(line)
		if got != want || ok != (want != "") || (ok && level != Warning) {
			t.Fatalf("%q: %q %v %q", line, got, ok, level)
		}
	}
}

func TestReadSkipsOverlongRecord(t *testing.T) {
	l := New()
	j := &Journal{Log: l}
	long := `{"__CURSOR":"x","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"` + strings.Repeat("a", maxJournalLine) + `"}`
	ok := `{"__CURSOR":"y","__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for u from 192.0.2.1 port 1 ssh2"}`
	j.read(context.Background(), strings.NewReader(long+"\n"+ok+"\n"))
	if got := messages(l, Access); len(got) != 1 || j.cursor != "y" {
		t.Fatal(got, j.cursor)
	}
}

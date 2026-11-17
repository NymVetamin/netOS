package eventlog

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDNSQueryFormats(t *testing.T) {
	for _, c := range []struct{ line, client, text string }{
		{"Nov 16 10:00:00 dnsmasq[123]: query[A] example.com from 192.168.1.5", "192.168.1.5", "example.com (A)"},
		{"query[AAAA] ipv6.example from fd00::5", "fd00::5", "ipv6.example (AAAA)"},
		{"info: 192.168.1.7 example.org. HTTPS IN", "192.168.1.7", "example.org (HTTPS)"},
		{`time=2026-10-16T00:00:00Z level=DEBUG msg=in prefix=proxy line_num=7 line=";example.org.\tIN\t A"`, "dnsproxy", "example.org (A)"},
		{"2026/10/16 00:00:00 in: ;example.net. IN AAAA", "dnsproxy", "example.net (AAAA)"},
	} {
		client, text, ok := DNSQuery(c.line)
		if !ok || client != c.client || text != c.text {
			t.Errorf("%q -> %q %q %v", c.line, client, text, ok)
		}
	}
	for _, line := range []string{
		"Nov 16 10:00:00 dnsmasq[123]: reply example.com is 192.0.2.1",
		"Nov 16 10:00:00 dnsmasq[123]: forwarded example.com to 1.1.1.1",
		"info: 192.168.1.7 example.org. A IN NOERROR 0.010 0 45",
		"info: not-an-ip example.org. A IN",
		`level=DEBUG msg=out line_num=7 line=";example.org.\tIN\t A"`,
		"started, version 2.90 cachesize 150",
	} {
		if _, _, ok := DNSQuery(line); ok {
			t.Errorf("not a query: %q", line)
		}
	}
}

func TestUnboundQueriesOnlyWithQueryLog(t *testing.T) {
	l := New()
	enabled := false
	j := &Journal{Log: l, DNS: func() bool { return enabled }}
	line := `{"__CURSOR":"a","__REALTIME_TIMESTAMP":"1","_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: 192.168.1.7 example.org. A IN"}`
	feed(j, time.Now(), line)
	enabled = true
	feed(j, time.Now(), line, `{"__CURSOR":"b","__REALTIME_TIMESTAMP":"2","_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: 192.168.1.7 example.org. A IN NOERROR 0.01 0 45"}`)
	if got := messages(l, DNS); strings.Join(got, "\n") != "info 192.168.1.7: example.org (A)" {
		t.Fatal(got)
	}
}

// A refill reads each group separately up to the journal head: a flood of DNS
// queries cannot push service history out, records are merged in time order,
// and the live follower continues after the head cursor.
func TestRefillPerGroupUpToHead(t *testing.T) {
	var calls [][]string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		joined := strings.Join(args, " ")
		switch {
		case args[len(args)-1] == "--lines=1":
			return []byte(`{"__CURSOR":"head","__REALTIME_TIMESTAMP":"1792000000123456"}` + "\n"), nil
		case strings.Contains(joined, "_PID=1"):
			return []byte(unitRecord("u1", msgStarted, "netos-dnsmasq.service", ``) + "\n"), nil
		case strings.Contains(joined, "SYSLOG_IDENTIFIER=sshd"):
			return []byte(`{"__CURSOR":"s1","__REALTIME_TIMESTAMP":"1791999999000000","_UID":"0","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for root from 192.0.2.9 port 1 ssh2"}` + "\n"), nil
		case strings.Contains(joined, "_SYSTEMD_UNIT=netos-unbound.service"):
			var b strings.Builder
			for i := Size - 1; i >= 0; i-- {
				fmt.Fprintf(&b, `{"__CURSOR":"d%d","__REALTIME_TIMESTAMP":"%d","_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: 192.168.1.7 q%d.example. A IN"}`+"\n", i, 1792000000000001+i, i)
			}
			return []byte(b.String()), nil
		}
		return nil, fmt.Errorf("No entries")
	}
	l := New()
	j := &Journal{Log: l, Run: run, DNS: func() bool { return true }}
	j.refill(context.Background())
	if j.cursor != "head" {
		t.Fatal(j.cursor)
	}
	if len(calls) != 1+len(journalGroups) {
		t.Fatal(len(calls))
	}
	for _, c := range calls[1:] {
		if !strings.Contains(strings.Join(c, " "), "--cursor=head") || !strings.Contains(strings.Join(c, " "), "--reverse") || !strings.Contains(strings.Join(c, " "), "--lines=1000") {
			t.Fatal(c)
		}
	}
	if got := messages(l, Services); len(got) != 1 || messages(l, Access)[0] != "info SSH: вход root с 192.0.2.9 (пароль)" || len(messages(l, DNS)) != Size {
		t.Fatal(got, messages(l, Access), len(messages(l, DNS)))
	}
	// Time order across groups: the SSH login (older) precedes the service start.
	ssh, _, _ := l.Since(Access, "", 0)
	svc, _, _ := l.Since(Services, "", 0)
	if ssh.Events[0].Seq != 1 || svc.Events[0].Seq <= ssh.Events[0].Seq {
		t.Fatal(ssh.Events, svc.Events)
	}
}

// A unit that failed seconds before netosd started is history all the same:
// the refill must not run a reason lookup per failure.
func TestRefillNeverLooksUpReasons(t *testing.T) {
	failed := fmt.Sprintf(`{"__CURSOR":"f","__REALTIME_TIMESTAMP":"%d","_PID":"1","MESSAGE_ID":"%s","UNIT":"netos-x.service","UNIT_RESULT":"exit-code","INVOCATION_ID":"0123456789abcdef0123456789abcdef"}`, time.Now().Add(-10*time.Second).UnixMicro(), msgFailed)
	lookups := 0
	l := New()
	j := &Journal{Log: l, Reason: func(context.Context, string) string { lookups++; return "why" }}
	j.Run = func(_ context.Context, args ...string) ([]byte, error) {
		if joined := strings.Join(args, " "); args[len(args)-1] == "--lines=1" || strings.Contains(joined, "_PID=1") {
			return []byte(failed + "\n"), nil
		}
		return nil, fmt.Errorf("No entries")
	}
	j.refill(context.Background())
	if got := messages(l, Services); lookups != 0 || len(got) != 1 || got[0] != "error netos-x: сбой: процесс завершился с ошибкой" {
		t.Fatal(lookups, got)
	}
	// A fresh failure arriving live does get its reason (another unit: a
	// repeated failure of the same one reads as the restart limit).
	j.Handle(context.Background(), []byte(strings.Replace(failed, "netos-x", "netos-y", 1)), time.Now())
	if lookups != 1 {
		t.Fatal(lookups)
	}
}

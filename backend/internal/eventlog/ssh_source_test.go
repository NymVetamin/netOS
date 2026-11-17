package eventlog

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestSSHRequiresTrustedRootOrigin(t *testing.T) {
	for _, uid := range []string{"", "65534", "0"} {
		for _, tag := range []string{"sshd", "sshd-session", "sshd-fake"} {
			l := New()
			j := &Journal{Log: l}
			raw, _ := json.Marshal(map[string]string{"__CURSOR": "test", "__REALTIME_TIMESTAMP": "1", "_UID": uid, "SYSLOG_IDENTIFIER": tag, "MESSAGE": "Accepted publickey for root from 192.0.2.1 port 1234 ssh2"})
			j.Handle(context.Background(), raw, time.Now())
			page, _, _ := l.Since(Access, "", 0)
			want := 0
			if uid == "0" && tag != "sshd-fake" {
				want = 1
			}
			if len(page.Events) != want || j.cursor != "test" {
				t.Errorf("uid=%q tag=%q: events=%d want=%d cursor=%q", uid, tag, len(page.Events), want, j.cursor)
			}
		}
	}
}

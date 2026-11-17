package eventlog

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRefillCursorBoundaryAndEqualTimeOrder(t *testing.T) {
	for _, laterTime := range []int64{100000000, 40000000} {
		t.Run(fmt.Sprint(laterTime), func(t *testing.T) {
			record := func(cursor, user string, at int64) string {
				return fmt.Sprintf(`{"__CURSOR":%q,"__REALTIME_TIMESTAMP":%q,"_UID":"0","SYSLOG_IDENTIFIER":"sshd","MESSAGE":%q}`, cursor, fmt.Sprint(at), "Accepted publickey for "+user+" from 192.0.2.1 port 2222 ssh2")
			}
			older := record("older", "older", 100000000)
			head := record("head", "head", 100000000)
			later := record("later", "later", laterTime)
			l := New()
			j := &Journal{Log: l, Run: func(_ context.Context, args ...string) ([]byte, error) {
				if slices.Contains(args, "--lines=1") {
					return []byte(head), nil
				}
				if !slices.Contains(args, "SYSLOG_IDENTIFIER=sshd") {
					return nil, nil
				}
				// journalctl's time boundary includes the later cursor too:
				// reproduced on Linux with a backward clock adjustment.
				if slices.Contains(args, "--cursor=head") && slices.Contains(args, "--reverse") {
					return []byte(head + "\n" + older), nil
				}
				return []byte(older + "\n" + head + "\n" + later), nil
			}}
			j.refill(context.Background())
			if j.cursor != "head" {
				t.Fatal("follower boundary changed", j.cursor)
			}
			p, _, _ := l.Since(Access, "", 0)
			if len(p.Events) != 2 || !strings.Contains(p.Events[0].Message, "head") || !strings.Contains(p.Events[1].Message, "older") {
				t.Fatalf("history crossed cursor boundary or reversed equal-time order: %+v", p.Events)
			}
			j.Handle(context.Background(), []byte(later), time.Now())
			delta, _, _ := l.Since(Access, p.Epoch, p.Latest)
			if delta.Reset || len(delta.Events) != 1 || !strings.Contains(delta.Events[0].Message, "later") {
				t.Fatal("live continuation lost", delta)
			}
		})
	}
}

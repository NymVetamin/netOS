package eventlog

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAllCursorOverflowMatchesFreshSnapshot(t *testing.T) {
	l := New()
	l.Add(time.Unix(3000, 0), System, Info, "test", "newest before pause")
	first, _, _ := l.Since("all", "", 0)
	for i := 0; i < Size; i++ {
		l.Add(time.Unix(10, 0), DNS, Info, "test", "equal timestamps")
	}
	delta, _, _ := l.Since("all", first.Epoch, first.Latest)
	if delta.Reset || len(delta.Events) != Size || delta.Events[0].Seq != delta.Latest {
		t.Fatal("exactly one page of new events should remain incremental")
	}
	l.Add(time.Unix(20, 0), Access, Info, "test", "after pause")
	resumed, _, _ := l.Since("all", first.Epoch, first.Latest)
	fresh, _, _ := l.Since("all", "", 0)
	if !resumed.Reset || resumed.Latest != fresh.Latest || !slices.Equal(resumed.Events, fresh.Events) ||
		len(resumed.Events) != Size || resumed.Events[0].Message != "newest before pause" {
		t.Fatal("overflow did not return the current snapshot")
	}
	next, _, _ := l.Since("all", resumed.Epoch, resumed.Latest)
	if next.Reset || len(next.Events) != 0 {
		t.Fatal("unexpected events after reset")
	}
	one, _, _ := l.Since(Access, first.Epoch, first.Latest)
	if one.Reset || len(one.Events) != 1 {
		t.Fatal("unrelated topics reset the filtered log")
	}
}

func BenchmarkAllCursorContinuation(b *testing.B) {
	for _, n := range []int{32, Size + 1, Size * len(Topics)} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			l := New()
			l.Add(time.Unix(3000, 0), System, Info, "test", "initial")
			first, _, _ := l.Since("all", "", 0)
			for i := 0; i < n; i++ {
				l.Add(time.Unix(int64(i%23), 0), Topics[i%len(Topics)], Info, "test", "sample")
			}
			b.ReportAllocs()
			for b.Loop() {
				l.Since("all", first.Epoch, first.Latest)
			}
		})
	}
}

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

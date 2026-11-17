package eventlog

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestJournalHistoryPreservesNewerLiveEvents(t *testing.T) {
	l := New()
	l.Add(time.Unix(3000, 0), Access, Info, "panel", "recent")
	first, _, _ := l.Since(Access, "", 0)
	j := &Journal{Log: l, Run: func(_ context.Context, args ...string) ([]byte, error) {
		if args[len(args)-1] == "--lines=1" {
			return []byte(`{"__CURSOR":"head","__REALTIME_TIMESTAMP":"4000000000"}`), nil
		}
		if !strings.Contains(strings.Join(args, " "), "SYSLOG_IDENTIFIER=sshd") {
			return nil, nil
		}
		var out strings.Builder
		for i := Size - 1; i >= 0; i-- {
			fmt.Fprintf(&out, `{"__CURSOR":"old%d","__REALTIME_TIMESTAMP":"%d","_UID":"0","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for root from 192.0.2.1 port 1234 ssh2"}`+"\n", i, int64(1000+i)*1000000)
		}
		return []byte(out.String()), nil
	}}
	j.refill(context.Background())
	p, _, _ := l.Since(Access, first.Epoch, first.Latest)
	if !p.Reset || len(p.Events) != Size || p.Events[0].Message != "recent" {
		t.Fatalf("newer panel event lost or history not reset: count=%d reset=%v first=%+v", len(p.Events), p.Reset, p.Events[0])
	}
	for i := 1; i < len(p.Events); i++ {
		if p.Events[i].Time > p.Events[i-1].Time {
			t.Fatal("history is not ordered by time")
		}
	}
	l.Add(time.Unix(4001, 0), Access, Info, "panel", "next")
	delta, _, _ := l.Since(Access, p.Epoch, p.Latest)
	if delta.Reset || len(delta.Events) != 1 || delta.Events[0].Message != "next" {
		t.Fatal("live continuation broken", delta)
	}
}

func TestMergeHistoryOrderTiesAndEmpty(t *testing.T) {
	for _, historyNewer := range []bool{false, true} {
		l, history := New(), New()
		at := time.Unix(100, 0)
		l.Add(at, Access, Info, "live", "live tie")
		history.Add(at, Access, Info, "old", "history tie")
		l.Add(at, DNS, Info, "dns", "untouched")
		initial, changed, _ := l.Since("all", "", 0)
		l.MergeHistory(New())
		select {
		case <-changed:
			t.Fatal("empty import woke clients")
		default:
		}
		other := at.Add(-time.Second)
		if historyNewer {
			other = at.Add(time.Second)
		}
		history.Add(other, Access, Info, "old", "different")
		// Simulate a live event arriving while the history is being read.
		l.Add(at.Add(2*time.Second), Access, Info, "live", "during read")
		l.MergeHistory(history)
		p, _, _ := l.Since(Access, initial.Epoch, initial.Latest)
		if !p.Reset || len(p.Events) != 4 || p.Events[0].Message != "during read" {
			t.Fatal(p)
		}
		for i, e := range p.Events {
			if e.Message == "live tie" && (i+1 >= len(p.Events) || p.Events[i+1].Message != "history tie") {
				t.Fatal("live tie preference lost", p)
			}
		}
		if dns, _, _ := l.Since(DNS, initial.Epoch, initial.Latest); dns.Reset || len(dns.Events) != 0 {
			t.Fatal("unrelated topic reset", dns)
		}
		if again, _, _ := l.Since(Access, p.Epoch, p.Latest); again.Reset || len(again.Events) != 0 {
			t.Fatal("import repeats after acknowledgment", again)
		}
	}
}

func TestJournalLANHistoryUsesBatchAndSharedLeaseState(t *testing.T) {
	l := New()
	l.Add(time.Unix(3000, 0), DHCP, Info, "live", "newer")
	first, _, _ := l.Since(DHCP, "", 0)
	lan := &LAN{Log: l}
	line := "DHCPACK(br0) 192.0.2.1 aa:bb:cc:dd:ee:01 host"
	j := &Journal{Log: l, LAN: lan, Run: func(_ context.Context, args ...string) ([]byte, error) {
		if args[len(args)-1] == "--lines=1" {
			return []byte(`{"__CURSOR":"head","__REALTIME_TIMESTAMP":"4000000000"}`), nil
		}
		if strings.Contains(strings.Join(args, " "), "_SYSTEMD_UNIT=netos-dnsmasq.service") {
			return []byte(`{"__CURSOR":"lease","__REALTIME_TIMESTAMP":"1000000000","_SYSTEMD_UNIT":"netos-dnsmasq.service","MESSAGE":"` + line + `"}`), nil
		}
		return nil, nil
	}}
	j.refill(context.Background())
	p, _, _ := l.Since(DHCP, first.Epoch, first.Latest)
	if !p.Reset || len(p.Events) != 2 || p.Events[0].Message != "newer" || lan.Log != l {
		t.Fatal("LAN history escaped batch", p)
	}
	lan.DHCP(time.Unix(4000, 0), line)
	if next, _, _ := l.Since(DHCP, p.Epoch, p.Latest); next.Reset || len(next.Events) != 0 {
		t.Fatal("history no longer seeds shared renewal suppression", next)
	}
}

func BenchmarkMergeHistory(b *testing.B) {
	for _, n := range []int{100, Size, Size * len(Topics)} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Include preparation and live state: two bounded logs, one
				// timestamp interleaving of two sources, and the import itself.
				live, history := New(), New()
				for k := 0; k < n; k++ {
					topic := Access
					if n > Size {
						topic = Topics[k%len(Topics)]
					}
					live.Add(time.Unix(int64(k*2+1), 0), topic, Info, "panel", "login")
					history.Add(time.Unix(int64(k*2), 0), topic, Info, "SSH", "login")
				}
				live.MergeHistory(history)
			}
		})
	}
}

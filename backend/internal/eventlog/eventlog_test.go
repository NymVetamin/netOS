package eventlog

import (
	"fmt"
	"testing"
	"time"
)

func TestRingKeepsNewestAndReportsLoss(t *testing.T) {
	l := New()
	at := time.Unix(100, 0)
	for i := 1; i <= Size+5; i++ {
		l.Add(at, Firewall, Info, "r", fmt.Sprint(i))
	}
	l.Add(at, Services, Info, "u", "service")
	p, _, ok := l.Since(Firewall, "", 0)
	if !ok || len(p.Events) != Size || p.Events[0].Message != fmt.Sprint(Size+5) || p.Events[Size-1].Message != "6" || !p.Reset {
		t.Fatalf("ring: %d first=%v", len(p.Events), p.Events[0])
	}
	// A client that saw event 3 lost 4 and 5 to rotation: it must reload.
	if p, _, _ = l.Since(Firewall, p.Epoch, 3); !p.Reset {
		t.Fatal("lost events not reported")
	}
	// Up to date: nothing new, no reset; another topic does not leak in.
	latest := p.Latest
	if p, _, _ = l.Since(Firewall, p.Epoch, latest); p.Reset || len(p.Events) != 0 {
		t.Fatal(p)
	}
	l.Add(at, Firewall, Info, "r", "new")
	if p, _, _ = l.Since(Firewall, p.Epoch, latest); p.Reset || len(p.Events) != 1 || p.Events[0].Message != "new" {
		t.Fatal(p)
	}
}

func TestAllMergesTopicsNewestFirstWithoutDuplicates(t *testing.T) {
	l := New()
	at := time.Unix(100, 0)
	l.Add(at, Services, Info, "a", "1")
	l.Add(at, Access, Info, "b", "2")
	l.Add(at, Services, Error, "a", "3")
	l.Add(at, "unknown", Info, "x", "ignored")
	l.Add(at, Access, Info, "b", "")
	p, _, _ := l.Since("all", "", 0)
	if len(p.Events) != 3 || p.Events[0].Message != "3" || p.Events[1].Message != "2" || p.Events[2].Message != "1" {
		t.Fatal(p.Events)
	}
	if p, _, _ = l.Since("all", p.Epoch, 2); len(p.Events) != 1 || p.Events[0].Seq != 3 || p.Reset {
		t.Fatal(p)
	}
	if _, _, ok := l.Since("bogus", p.Epoch, 0); ok {
		t.Fatal("unknown topic accepted")
	}
}

func TestRestartedLogResetsClient(t *testing.T) {
	old := New()
	old.Add(time.Unix(1, 0), System, Info, "s", "x")
	p, _, _ := old.Since("all", "", 0)
	l := New()
	l.Add(time.Unix(2, 0), System, Info, "s", "y")
	if q, _, _ := l.Since("all", p.Epoch+"x", 1); !q.Reset || len(q.Events) != 1 {
		t.Fatal(q)
	}
	// Sequence ahead of the log (restart with same epoch is impossible, but a
	// forged after must not hide events).
	if q, _, _ := l.Since("all", "", 50); !q.Reset {
		t.Fatal(q)
	}
}

func TestChangedClosesOnAdd(t *testing.T) {
	l := New()
	_, changed, _ := l.Since("all", "", 0)
	l.Add(time.Now(), DNS, Info, "d", "q")
	select {
	case <-changed:
	default:
		t.Fatal("waiter not woken")
	}
}

// Add is O(1) and Since is O(returned) for a topic; the "all" view sorts at
// most Topics*Size events, only when a viewer opens the log.
func BenchmarkAdd(b *testing.B) {
	l := New()
	at := time.Now()
	for b.Loop() {
		l.Add(at, Firewall, Info, "rule", "TCP 192.0.2.1:1 → 192.0.2.2:2")
	}
}

func BenchmarkSinceAllFull(b *testing.B) {
	l := New()
	at := time.Now()
	for i := 0; i < Size*len(Topics); i++ {
		l.Add(at, Topics[i%len(Topics)], Info, "s", "m")
	}
	for b.Loop() {
		l.Since("all", "", 0)
	}
}

// Package eventlog keeps the router's human-readable event log in memory:
// a fixed ring per topic, like the memory log of a hardware router. Nothing is
// written to disk; journal-backed topics are refilled from journald on start.
package eventlog

import (
	"cmp"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Size is the number of events kept per topic and returned per view.
const Size = 1000

const (
	Services = "services"
	VPN      = "vpn"
	WiFi     = "wifi"
	DHCP     = "dhcp"
	Internet = "internet"
	Access   = "access"
	Firewall = "firewall"
	DNS      = "dns"
	System   = "system"
)

// Topics lists every topic in display order; "all" is the union of them.
var Topics = []string{Services, VPN, WiFi, DHCP, Internet, Access, Firewall, DNS, System}

const (
	Info    = "info"
	Warning = "warning"
	Error   = "error"
)

type Event struct {
	Seq     uint64 `json:"seq"`
	Time    int64  `json:"time"` // Unix milliseconds
	Topic   string `json:"topic"`
	Level   string `json:"level"`
	Source  string `json:"source"`
	Message string `json:"message"`
}

type ring struct {
	events  [Size]Event
	next    int // index of the slot the next event overwrites
	count   int
	dropped uint64 // highest Seq overwritten; 0 when nothing was lost
}

func (r *ring) add(e Event) {
	if r.count == Size {
		r.dropped = r.events[r.next].Seq
	} else {
		r.count++
	}
	r.events[r.next] = e
	r.next = (r.next + 1) % Size
}

// newer appends events with Seq > after, newest first. Cost is O(returned).
func (r *ring) newer(after uint64, out []Event) []Event {
	for i := 1; i <= r.count; i++ {
		e := r.events[(r.next-i+Size)%Size]
		if e.Seq <= after {
			break
		}
		out = append(out, e)
	}
	return out
}

type Log struct {
	epoch   string
	mu      sync.Mutex
	seq     uint64
	rings   map[string]*ring
	changed chan struct{}
}

func New() *Log {
	l := &Log{epoch: strconv.FormatInt(time.Now().UnixNano(), 36), rings: map[string]*ring{}, changed: make(chan struct{})}
	for _, t := range Topics {
		l.rings[t] = &ring{}
	}
	return l
}

// Add records one event. Unknown topics and empty messages are ignored.
func (l *Log) Add(at time.Time, topic, level, source, message string) {
	if l == nil || message == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.rings[topic]
	if r == nil {
		return
	}
	l.seq++
	r.add(Event{Seq: l.seq, Time: at.UnixMilli(), Topic: topic, Level: level, Source: source, Message: message})
	close(l.changed)
	l.changed = make(chan struct{})
}

type Page struct {
	Epoch  string  `json:"epoch"`
	Latest uint64  `json:"latest"`
	Reset  bool    `json:"reset"`
	Events []Event `json:"events"`
}

// Since returns events of topic ("all" for every topic) newer than after,
// newest first, at most Size. Reset tells the client to replace its list:
// a different epoch (restart) or events lost to rotation since after.
// Changed is closed by the next Add.
func (l *Log) Since(topic, epoch string, after uint64) (Page, <-chan struct{}, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if topic != "all" && l.rings[topic] == nil {
		return Page{}, nil, false
	}
	if epoch != l.epoch || after > l.seq {
		after = 0
	}
	p := Page{Epoch: l.epoch, Latest: l.seq, Reset: after == 0, Events: []Event{}}
	for _, t := range Topics {
		if (topic == "all" || t == topic) && l.rings[t].dropped > after {
			// The client missed rotated events: it gets the whole list anew.
			p.Reset, after = true, 0
		}
	}
	for _, t := range Topics {
		if topic == "all" || t == topic {
			p.Events = l.rings[t].newer(after, p.Events)
		}
	}
	if p.Reset {
		// A full list is ordered by event time: refills from journald and
		// the audit table run concurrently, so insertion order is not time.
		slices.SortFunc(p.Events, func(a, b Event) int {
			if c := cmp.Compare(b.Time, a.Time); c != 0 {
				return c
			}
			return cmp.Compare(b.Seq, a.Seq)
		})
	} else if topic == "all" {
		// New events of every ring are newest-first; the union needs one order.
		slices.SortFunc(p.Events, func(a, b Event) int { return cmp.Compare(b.Seq, a.Seq) })
	}
	if len(p.Events) > Size {
		p.Events, p.Reset = p.Events[:Size], true
	}
	return p, l.changed, true
}

// Notifier returns a callback for uplink and channel monitors: kind names the
// object ("аплинк", "канал"), name is its configured name.
func (l *Log) Notifier(kind string) func(up bool, name, detail string) {
	return func(up bool, name, detail string) {
		if up {
			l.Add(time.Now(), Internet, Info, name, kind+" снова доступен")
			return
		}
		msg := kind + " недоступен"
		if detail != "" {
			msg += ": " + detail
		}
		l.Add(time.Now(), Internet, Warning, name, msg)
	}
}

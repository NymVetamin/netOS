package api

import (
	"fmt"
	"io"
	"math/rand"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type connectionFailingReader struct{}

func (connectionFailingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestTrackedConnectionScanFailureAndRetainedRows(t *testing.T) {
	for _, long := range []bool{false, true} {
		read := func() io.Reader {
			if long {
				return strings.NewReader(trackedSample + "\n" + strings.Repeat("x", 1<<20))
			}
			return io.MultiReader(strings.NewReader(trackedSample+"\n"), connectionFailingReader{})
		}
		old, got := connectionPage{}, connectionPage{}
		e1 := scanConnectionRows(read(), parseTrackedConnectionReference, connectionFilter{}, &old)
		e2 := scanConnectionRows(read(), parseTrackedConnection, connectionFilter{}, &got)
		if e1 == nil || e2 == nil || e1.Error() != e2.Error() || !reflect.DeepEqual(old, got) {
			t.Fatalf("scan error changed: %v / %v", e1, e2)
		}
		retained := got.Rows[0]
		var next connectionPage
		if err := scanConnectionRows(strings.NewReader(strings.ReplaceAll(trackedSample, "192.0.2.10", "192.0.2.11")), parseTrackedConnection, connectionFilter{}, &next); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(retained, old.Rows[0]) || next.Rows[0].Source.Address != "192.0.2.11" {
			t.Fatal("retained row changed or next scan stale")
		}
	}
}

func parseTrackedConnectionReference(line string) (diagnosticConnection, bool) {
	f := strings.Fields(line)
	c := diagnosticConnection{}
	if len(f) < 6 {
		return c, false
	}
	at := 0
	if f[0] == "ipv4" || f[0] == "ipv6" {
		at = 2
	}
	if len(f) < at+4 {
		return c, false
	}
	c.Protocol = strings.ToUpper(f[at])
	c.Timeout = connectionNumber(f[at+2])
	c.State = "TRACKED"
	if !strings.Contains(f[at+3], "=") && !strings.HasPrefix(f[at+3], "[") {
		c.State = f[at+3]
	}
	src, dst := 0, 0
	reply := false
	for _, value := range f[at+3:] {
		key, v, hasValue := strings.Cut(value, "=")
		if !hasValue {
			if value == "[UNREPLIED]" {
				c.State = "UNREPLIED"
			} else if value == "[ASSURED]" && c.State == "TRACKED" {
				c.State = "ASSURED"
			}
			continue
		}
		switch key {
		case "src":
			src++
			reply = src > 1
			if reply {
				c.ReplySource.Address = v
			} else {
				c.Source.Address = v
			}
		case "dst":
			dst++
			if dst > 1 {
				c.ReplyDestination.Address = v
			} else {
				c.Destination.Address = v
			}
		case "sport":
			if reply {
				c.ReplySource.Port = v
			} else {
				c.Source.Port = v
			}
		case "dport":
			if reply {
				c.ReplyDestination.Port = v
			} else {
				c.Destination.Port = v
			}
		case "packets":
			if reply {
				c.ReplyPackets = connectionNumber(v)
			} else {
				c.Packets = connectionNumber(v)
			}
		case "bytes":
			if reply {
				c.ReplyBytes = connectionNumber(v)
			} else {
				c.Bytes = connectionNumber(v)
			}
		}
	}
	if src != 2 || dst != 2 || c.Timeout == nil {
		return c, false
	}
	if c.Source != c.ReplyDestination {
		c.NAT = "SNAT"
	}
	if c.Destination != c.ReplySource {
		if c.NAT != "" {
			c.NAT += " + "
		}
		c.NAT += "DNAT"
	}
	return c, true
}

func TestTrackedConnectionEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	fields := strings.Fields(trackedSample)
	for i := 0; i < 5000; i++ {
		f := append([]string(nil), fields...)
		if i%2 == 0 {
			rng.Shuffle(len(f), func(i, j int) { f[i], f[j] = f[j], f[i] })
		}
		if i%3 == 0 {
			f = f[:rng.Intn(len(f)+1)]
		}
		if i%5 == 0 {
			f = append(f, strings.Repeat(" ignored=1", 100))
		}
		line := strings.Join(f, []string{" ", "\t", "\u2003", "\n"}[i%4])
		old, ok := parseTrackedConnectionReference(line)
		got, valid := parseTrackedConnection(line)
		if ok != valid || !reflect.DeepEqual(old, got) {
			t.Fatalf("case%d differs", i)
		}
	}
	data := strings.Repeat(trackedSample+"\n", 250) + "invalid\n"
	for _, query := range []string{"", "protocol=UDP", "nat=SNAT", "address=192.0.2.0/24&ports=443&side=dst", "address=203.0.113.1"} {
		filter, e := parseConnectionFilter(httptest.NewRequest("GET", "/?"+query, nil))
		if e != nil {
			t.Fatal(e)
		}
		for _, n := range []int{-1, 0, 1, 2, 3} {
			old, got := connectionPage{Page: n}, connectionPage{Page: n}
			e1 := scanConnectionRows(strings.NewReader(data), parseTrackedConnectionReference, filter, &old)
			e2 := scanConnectionRows(strings.NewReader(data), parseTrackedConnection, filter, &got)
			if e1 != e2 || !reflect.DeepEqual(old, got) {
				t.Fatalf("page%d query%s differs", n, query)
			}
		}
	}
}
func BenchmarkTrackedConnectionComparison(b *testing.B) {
	for _, n := range []int{1000, 100000} {
		data := strings.Repeat(trackedSample+"\n", n)
		for _, old := range []bool{true, false} {
			b.Run(fmt.Sprintf("%d/old=%t", n, old), func(b *testing.B) {
				parse := parseTrackedConnection
				if old {
					parse = parseTrackedConnectionReference
				}
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					page := connectionPage{Page: 3}
					if e := scanConnectionRows(strings.NewReader(data), parse, connectionFilter{}, &page); e != nil {
						b.Fatal(e)
					}
					if page.Total != n {
						b.Fatal(page.Total)
					}
				}
			})
		}
	}
}

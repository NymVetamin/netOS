package api

import (
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"testing"
)

func originalTorchSnapshot(t *torchReader, seconds float64, page ...int) map[string]any {
	rows := make([]torchFlow, 0, len(t.flows))
	for _, f := range t.flows {
		row := *f
		if seconds > 0 {
			row.Bitrate = float64(row.Bytes) * 8 / seconds
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes != rows[j].Bytes {
			return rows[i].Bytes > rows[j].Bytes
		}
		if rows[i].Source != rows[j].Source {
			return rows[i].Source < rows[j].Source
		}
		if rows[i].Destination != rows[j].Destination {
			return rows[i].Destination < rows[j].Destination
		}
		if rows[i].Protocol != rows[j].Protocol {
			return rows[i].Protocol < rows[j].Protocol
		}
		if rows[i].SourcePort != rows[j].SourcePort {
			return rows[i].SourcePort < rows[j].SourcePort
		}
		return rows[i].DestinationPort < rows[j].DestinationPort
	})
	if len(page) > 0 {
		start := page[0] * 100
		if start < 0 || start > len(rows) {
			start = len(rows)
		}
		rows = rows[start:min(start+100, len(rows))]
	}
	return map[string]any{"flows": rows, "total_flows": len(t.flows), "packets": t.packets, "skipped": t.skipped}
}

func snapshotFixture(n int) *torchReader {
	t := newTorchReader()
	for i := 0; i < n; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		t.flows[torchKey{source: a}] = &torchFlow{Source: a.String(), Destination: "192.0.2.1", Protocol: "UDP", SourcePort: uint16(i), Bytes: uint64((i * 7919) % 97)}
	}
	return t
}

func TestTorchSnapshotPagesEquivalent(t *testing.T) {
	for _, n := range []int{0, 1, 25, 100, 401, 1000, 10000} {
		r := snapshotFixture(n)
		i := 0
		for _, f := range r.flows {
			f.Source = fmt.Sprintf("source-%d", i%3)
			f.Destination = fmt.Sprintf("dest-%d", i%5)
			f.Protocol = []string{"TCP", "UDP", "IP"}[i%3]
			f.SourcePort = uint16(i)
			f.DestinationPort = uint16(i % 11)
			i++
		}
		for _, seconds := range []float64{-1, 0, 2, 60} {
			for p := -1; p <= n/100+1; p++ {
				if !reflect.DeepEqual(originalTorchSnapshot(r, seconds, p), r.snapshot(seconds, p)) {
					t.Fatalf("n=%d page=%d seconds=%v", n, p, seconds)
				}
			}
			if !reflect.DeepEqual(originalTorchSnapshot(r, seconds), r.snapshot(seconds)) {
				t.Fatal("full snapshot")
			}
		}
		for _, p := range []int{int(^uint(0) >> 1), int(^uint(0)>>1)/100 + 1} {
			if !reflect.DeepEqual(originalTorchSnapshot(r, 2, p), r.snapshot(2, p)) {
				t.Fatal("overflow page changed")
			}
		}
		previous := r.snapshot(2, 0)
		saved := append([]torchFlow{}, previous["flows"].([]torchFlow)...)
		for _, f := range r.flows {
			f.Bytes += 500
			f.Packets++
		}
		if !reflect.DeepEqual(saved, previous["flows"]) {
			t.Fatal("response aliases live flow")
		}
		if !reflect.DeepEqual(originalTorchSnapshot(r, 2, 0), r.snapshot(2, 0)) {
			t.Fatal("stale counts")
		}
	}
}

func TestTorchSnapshotConcurrentCapture(t *testing.T) {
	j := &diagnosticJob{torch: newTorchReader()}
	w := &capturePacketWriter{job: j}
	data := pcapFixture(1, 1000)
	if _, err := w.Write(data[:24]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 100; i++ {
			if _, err := w.Write(data[24:]); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 100; i++ {
		j.mu.Lock()
		got := j.torch.snapshot(2, i%10)
		want := originalTorchSnapshot(j.torch, 2, i%10)
		j.mu.Unlock()
		if !reflect.DeepEqual(want, got) {
			t.Fatal("inconsistent snapshot")
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if j.torch.packets != 100000 || len(j.torch.flows) != 1000 {
		t.Fatalf("lost counts: %d/%d", j.torch.packets, len(j.torch.flows))
	}
}

var torchSnapshotBenchmarkSink map[string]any

func BenchmarkTorchSnapshotComparison(b *testing.B) {
	for _, n := range []int{100, 10000, 100000} {
		r := snapshotFixture(n)
		pages := []int{0}
		if n >= 1000 {
			pages = append(pages, n/1000, n/400-2, n/200)
		}
		for _, page := range pages {
			for _, old := range []bool{true, false} {
				b.Run(fmt.Sprintf("flows%d/page%d/old%v", n, page, old), func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						if old {
							torchSnapshotBenchmarkSink = originalTorchSnapshot(r, 60, page)
						} else {
							torchSnapshotBenchmarkSink = r.snapshot(60, page)
						}
					}
				})
			}
		}
	}
}

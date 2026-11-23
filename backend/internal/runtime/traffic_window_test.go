package runtime

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestTrafficWindowInclusiveDuplicateBounds(t *testing.T) {
	base := time.Unix(1800000000, 0)
	h := &TrafficHistory{Interval: time.Second}
	for i, second := range []int{0, 1, 1, 2, 3} {
		h.points = append(h.points, TrafficPoint{At: base.Add(time.Duration(second) * time.Second), Interfaces: map[string]TrafficRate{
			"wan": {RXBytes: int64(i), RXBPS: int64(10 * i)},
		}})
	}
	for repeat := 0; repeat < 2; repeat++ {
		got := h.Window(base.Add(time.Second), base.Add(2*time.Second), nil, 600)
		want := []TrafficPoint{
			{At: base.Add(time.Second), Interfaces: map[string]TrafficRate{"wan": {RXBytes: 2, RXBPS: 15}}},
			{At: base.Add(2 * time.Second), Interfaces: map[string]TrafficRate{"wan": {RXBytes: 3, RXBPS: 30}}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("inclusive duplicate bounds: got %+v, want %+v", got, want)
		}
		for _, bounds := range [][2]int{{-2, -1}, {4, 5}, {2, 1}} {
			if got := h.Window(base.Add(time.Duration(bounds[0])*time.Second), base.Add(time.Duration(bounds[1])*time.Second), nil, 600); len(got) != 0 {
				t.Fatalf("empty bounds %v: %+v", bounds, got)
			}
		}
	}
	if got := (&TrafficHistory{}).Window(base, base, nil, 0); got == nil || len(got) != 0 {
		t.Fatalf("empty history must encode as array: %+v", got)
	}
}

func BenchmarkTrafficWindowResponse(b *testing.B) {
	for _, n := range []int{288, 20161} {
		for _, full := range []bool{false, true} {
			b.Run(fmt.Sprintf("points=%d/full=%t", n, full), func(b *testing.B) {
				base := time.Unix(1800000000, 0)
				h := &TrafficHistory{Interval: 30 * time.Second}
				for i := 0; i < n; i++ {
					h.points = append(h.points, TrafficPoint{At: base.Add(time.Duration(i) * h.Interval), Interfaces: map[string]TrafficRate{
						"wan": {RXBytes: int64(i * 100), RXBPS: 100}, "lan": {RXBPS: 200},
					}})
				}
				to := h.points[n-1].At
				from := to.Add(-2 * h.Interval)
				if full {
					from = base
				}
				b.ReportAllocs()
				for b.Loop() {
					points := h.Window(from, to, []string{"wan"}, 600)
					if len(points) == 0 || (!full && len(points) != 3) {
						b.Fatal("incorrect response")
					}
					if _, err := json.Marshal(map[string]any{"points": points, "interval_seconds": 30}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

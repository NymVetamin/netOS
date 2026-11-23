package config

import (
	"fmt"
	"math"
	"strconv"
	"testing"
)

func TestStaticRouteMetricRange(t *testing.T) {
	for _, destination := range []string{"192.0.2.0/24", "2001:db8::/64"} {
		for _, enabled := range []bool{false, true} {
			for _, metric := range []int64{-1, 0, 1, math.MaxUint32, math.MaxUint32 + 1, math.MaxInt64} {
				if strconv.IntSize == 32 && metric > math.MaxInt32 {
					continue
				}
				t.Run(fmt.Sprintf("%s/%t/%d", destination, enabled, metric), func(t *testing.T) {
					cfg := validRoutingConfig()
					cfg.Routing.Static[0].Destination = destination
					cfg.Routing.Static[0].Enabled = enabled
					cfg.Routing.Static[0].Metric = int(metric)
					for range 2 {
						if got := problem(t, cfg, "routing.static[0].metric", ""); got != (metric < 0 || metric > math.MaxUint32) {
							t.Fatalf("metric %d: error=%t", metric, got)
						}
					}
					cfg.Routing.Static[0].Metric = 1
					if result := cfg.Validate(); result.HasErrors() {
						t.Fatalf("corrected metric: %+v", result.Problems)
					}
				})
			}
		}
	}
}

func BenchmarkValidateStaticRouteMetrics(b *testing.B) {
	for _, n := range []int{16, 2048} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := validRoutingConfig()
			cfg.Routing.Static = make([]StaticRoute, n)
			for i := range cfg.Routing.Static {
				cfg.Routing.Static[i] = StaticRoute{ID: fmt.Sprint(i), Enabled: true, Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), Type: "blackhole", Metric: 100}
			}
			b.ReportAllocs()
			for b.Loop() {
				if result := cfg.Validate(); result.HasErrors() {
					b.Fatal(result.Problems)
				}
			}
		})
	}
}

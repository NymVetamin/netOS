package multiwan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestTickRetainsOnlyWantedAndEnabledPPPHistory(t *testing.T) {
	for _, mode := range []string{"off", "failover", "balance"} {
		for _, second := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/second=%v", mode, second), func(t *testing.T) {
				r := &responseRunner{respond: func(string) (string, error) { return "", errors.New("route read failed") }}
				c := New(r, t.TempDir(), nil)
				c.suppressed = map[string]string{}
				c.knownRoutes = map[string]string{"ppp": "old ppp", "disabled": "old disabled", "static": "old static", "gone": "old gone"}
				c.states = map[string]*linkState{"static": {Next: time.Now().Add(time.Hour)}}
				cfg := config.Default()
				cfg.MultiWAN.Enabled, cfg.MultiWAN.Mode = mode != "off", mode
				cfg.WANs = []config.WAN{
					{ID: "ppp", Index: 1, Enabled: true, Proto: "l2tp"},
					{ID: "disabled", Index: 2, Proto: "pppoe"},
					{ID: "static", Index: 3, Enabled: second, Proto: "static", Probe: config.Probe{Enabled: true}},
				}
				want := map[string]string{}
				if second {
					want["ppp"] = "old ppp"
					if mode != "off" {
						want["static"] = "old static"
					}
				}
				for i := 0; i < 2; i++ {
					c.tick(context.Background(), cfg)
					if !reflect.DeepEqual(c.knownRoutes, want) {
						t.Fatalf("history=%v want=%v", c.knownRoutes, want)
					}
				}
				wantReads := 0
				if second {
					wantReads = 2
				}
				if len(r.commands) != wantReads {
					t.Fatalf("retry reads: %v", r.commands)
				}
				// Configuration changes are seen on the next tick, without cached
				// membership keeping a disabled PPP route alive.
				cfg.WANs[0].Enabled = false
				c.tick(context.Background(), cfg)
				if _, exists := c.knownRoutes["ppp"]; exists {
					t.Fatal("disabled PPP history retained")
				}
			})
		}
	}
}

func BenchmarkIdleTick(b *testing.B) {
	for _, n := range []int{2, 20, 200} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := &fakeRunner{}
			c := New(r, b.TempDir(), nil)
			c.states = map[string]*linkState{}
			c.knownRoutes = map[string]string{}
			c.suppressed = map[string]string{}
			cfg := config.Default()
			cfg.MultiWAN.Enabled = true
			cfg.MultiWAN.Mode = "failover"
			cfg.WANs = nil
			for i := 0; i < n; i++ {
				id := fmt.Sprint(i)
				cfg.WANs = append(cfg.WANs, config.WAN{ID: id, Index: i + 1, Enabled: true, Proto: "static", Probe: config.Probe{Enabled: true}})
				c.states[id] = &linkState{Next: time.Now().Add(time.Hour)}
				c.knownRoutes[id] = "default dev wan" + id
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.tick(context.Background(), cfg)
			}
			b.StopTimer()
			if len(r.commands) != 0 || len(c.knownRoutes) != n {
				b.Fatalf("idle tick changed state: commands=%v known=%d", r.commands, len(c.knownRoutes))
			}
		})
	}
}

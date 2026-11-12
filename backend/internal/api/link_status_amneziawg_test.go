package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
)

type linkKindRunner struct {
	tool        string
	calls       int
	stale, fail bool
}

func (r *linkKindRunner) Run(_ context.Context, name string, _ ...string) (string, error) {
	r.calls++
	if r.fail || (r.tool != "" && name != r.tool) {
		return "", fmt.Errorf("unavailable interface for %s", name)
	}
	stamp := time.Now()
	if r.stale {
		stamp = stamp.Add(-10 * time.Minute)
	}
	return fmt.Sprintf("peer\t%d\n", stamp.Unix()), nil
}
func (r *linkKindRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestLiveLinksWireGuardKindsAndFreshness(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, awg := range []bool{false, true} {
			t.Run(fmt.Sprintf("shared=%v/awg=%v", shared, awg), func(t *testing.T) {
				cfg := &config.Config{VPNServers: []config.VPNServer{{ID: "server", Index: 1, Type: "wireguard", Enabled: true, Config: map[string]any{}}}, Channels: []config.Channel{{ID: "channel", Index: 1, Type: "wireguard", Enabled: true, Config: map[string]any{}}}}
				name := "wg-ch1"
				if shared {
					cfg.Channels[0].WireGuardPeer = &config.WireGuardPeerChannel{ServerID: "server", ServerIndex: 1, PeerID: "peer"}
					name = "wg-srv1"
				}
				target := cfg.Channels[0].Config
				if shared {
					target = cfg.VPNServers[0].Config
				}
				if awg {
					target["amneziawg"] = map[string]any{}
				}
				r := &linkKindRunner{tool: "wg"}
				if awg {
					r.tool = "awg"
				}
				s := &Server{Collector: &runtime.Collector{Runner: r}}
				stats := []runtime.InterfaceStat{{Name: name, Up: true}}
				check := func(want bool) {
					t.Helper()
					_, got := s.liveLinks(context.Background(), cfg, stats)
					if len(got) != 1 || got[0]["up"] != want {
						t.Fatalf("status=%v want=%v", got, want)
					}
				}
				check(true)
				check(true)
				r.stale = true
				check(false)
				r.stale = false
				r.fail = true
				check(false)
				r.fail = false
				check(true)
				s.ChannelHealth = downProbe(true)
				check(false)
				s.ChannelHealth = nil
				stats[0].Up = false
				before := r.calls
				check(false)
				if r.calls != before {
					t.Fatal("queried down interface")
				}
				stats[0].Up = true
				// A new snapshot must see the edited kind, not a previous cached lookup.
				if awg {
					delete(target, "amneziawg")
					r.tool = "wg"
				} else {
					target["amneziawg"] = map[string]any{}
					r.tool = "awg"
				}
				check(true)
				s.Collector = nil
				check(false)
			})
		}
	}
}

func BenchmarkLiveLinksSharedWireGuard(b *testing.B) {
	for _, n := range []int{25, 2500} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := &config.Config{}
			stats := make([]runtime.InterfaceStat, 0, n)
			for i := 1; i <= n; i++ {
				id := fmt.Sprint(i)
				cfg.VPNServers = append(cfg.VPNServers, config.VPNServer{ID: id, Index: i, Type: "wireguard", Config: map[string]any{"amneziawg": map[string]any{}}})
				cfg.Channels = append(cfg.Channels, config.Channel{ID: id, Type: "wireguard", Enabled: true, WireGuardPeer: &config.WireGuardPeerChannel{ServerID: id, ServerIndex: i}})
				stats = append(stats, runtime.InterfaceStat{Name: fmt.Sprintf("wg-srv%d", i), Up: true})
			}
			// Accept either tool here to measure both revisions with identical
			// handshake output; the regression tests assert the required tool.
			r := &linkKindRunner{}
			s := &Server{Collector: &runtime.Collector{Runner: r}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, got := s.liveLinks(context.Background(), cfg, stats)
				if len(got) != n || got[n-1]["up"] != true {
					b.Fatal("incorrect snapshot")
				}
			}
			b.ReportMetric(float64(r.calls)/float64(b.N), "commands/op")
		})
	}
}

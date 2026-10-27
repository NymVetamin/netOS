package channels

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestCachedFallbackStillRepairsRulesAndRetriesUDP(t *testing.T) {
	s, base := newTestSubsystem(t)
	runner := &udpRefreshRunner{channelRunner: base, failDelete: true, entriesRemain: true}
	s.Runner = runner
	cfg := channelConfig()
	ch := cfg.Channels[1]
	ch.FailMode, ch.Fallback = "fallback", "reserve"
	reserve := ch
	reserve.ID, reserve.Index = "reserve", 2
	cfg.Channels = []config.Channel{ch, reserve}
	resolver := newFallbackResolver(cfg, s.states)
	apply := func() error { return s.applyFallback(context.Background(), ch, resolver.resolve(ch)) }
	if err := apply(); err == nil {
		t.Fatal("UDP cleanup failure hidden")
	}
	runner.failDelete = false
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	if len(runner.deletes) != 2 {
		t.Fatalf("UDP retry count: %v", runner.deletes)
	}
	base.rules = "" // external drift must not be hidden by destination memoization
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	if len(runner.deletes) != 3 {
		t.Fatalf("lost rule was not repaired: %v", runner.deletes)
	}
}

func TestFallbackResolverMatchesOriginalWalk(t *testing.T) {
	rng := rand.New(rand.NewSource(733))
	modes := []string{"block", "direct", "fallback", ""}
	for trial := 0; trial < 5000; trial++ {
		cfg := config.Default()
		cfg.Channels = nil
		s := New(nil, "")
		n := 1 + rng.Intn(30)
		for i := 0; i < n; i++ {
			id := fmt.Sprint(i)
			if trial%4 == 0 && i > 0 {
				id = fmt.Sprint(rng.Intn(i))
			}
			ch := config.Channel{ID: id, Index: i + 1, Enabled: rng.Intn(4) != 0, Type: "xray", FailMode: modes[rng.Intn(len(modes))], Fallback: fmt.Sprint(rng.Intn(n + 2))}
			if rng.Intn(8) == 0 {
				ch.Type = "direct"
			}
			cfg.Channels = append(cfg.Channels, ch)
			if rng.Intn(3) != 0 {
				s.states[id] = &channelState{Down: rng.Intn(2) == 0}
			}
		}
		resolver := newFallbackResolver(cfg, s.states)
		for repeat := 0; repeat < 2; repeat++ {
			for _, i := range rng.Perm(n) {
				ch := cfg.Channels[i]
				if !ch.Enabled {
					continue
				}
				want := s.legacyFallbackRoute(cfg, ch)
				got := resolver.resolve(ch)
				if got != want {
					t.Fatalf("trial%d ch%+v got%+v want%+v cfg%+v", trial, ch, got, want, cfg.Channels)
				}
			}
		}
		// Health changes require a new resolver, just as the next monitor tick does.
		for _, state := range s.states {
			state.Down = !state.Down
		}
		resolver = newFallbackResolver(cfg, s.states)
		for _, ch := range cfg.Channels {
			if ch.Enabled {
				if got, want := resolver.resolve(ch), s.legacyFallbackRoute(cfg, ch); got != want {
					t.Fatalf("new health snapshot trial%d got%+v want%+v", trial, got, want)
				}
			}
		}
	}
}
func (s *Subsystem) legacyFallbackRoute(cfg *config.Config, ch config.Channel) fallbackRoute {
	target := ch
	seen := map[string]bool{}
	for {
		if seen[target.ID] {
			return fallbackRoute{}
		}
		seen[target.ID] = true
		switch target.FailMode {
		case "direct":
			return fallbackRoute{direct: true}
		case "fallback":
			fallback, ok := legacyChannelByID(cfg, target.Fallback)
			if !ok {
				return fallbackRoute{}
			}
			if fallback.Type == "direct" {
				return fallbackRoute{direct: true}
			}
			if state := s.states[fallback.ID]; state != nil && state.Down {
				target = fallback
				continue
			}
			return fallbackRoute{table: TableNumber(fallback)}
		default: // block
			// Recovery probes bind to the device without the client fwmark.
			// Block marked traffic at the rule, keeping probe routes usable.
			return fallbackRoute{}
		}
	}
}

type lookupProbeRunner struct{}

func (lookupProbeRunner) Run(context.Context, string, ...string) (string, error) { return "", nil }
func (lookupProbeRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", nil
}
func BenchmarkFallbackResolution(b *testing.B) {
	for _, n := range []int{2, 20, 200} {
		for _, deep := range []bool{false, true} {
			for _, indexed := range []bool{false, true} {
				b.Run(fmt.Sprintf("n%d/deep%v/index%v", n, deep, indexed), func(b *testing.B) {
					s := New(lookupProbeRunner{}, b.TempDir())
					cfg := config.Default()
					cfg.Channels = nil
					for i := 0; i < n; i++ {
						next := n - 1
						if deep {
							next = i + 1
						}
						ch := config.Channel{ID: fmt.Sprint(i), Index: i + 1, Enabled: true, Type: "xray", FailMode: "fallback", Fallback: fmt.Sprint(next)}
						if i == n-1 {
							ch.FailMode = "direct"
						}
						cfg.Channels = append(cfg.Channels, ch)
						s.states[ch.ID] = &channelState{Down: true}
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if indexed {
							resolver := newFallbackResolver(cfg, s.states)
							for _, ch := range cfg.Channels {
								if err := s.applyFallback(context.Background(), ch, resolver.resolve(ch)); err != nil {
									b.Fatal(err)
								}
							}
						} else {
							for _, ch := range cfg.Channels {
								if err := s.applyFallback(context.Background(), ch, s.legacyFallbackRoute(cfg, ch)); err != nil {
									b.Fatal(err)
								}
							}
						}
					}
				})
			}
		}
	}
}

func legacyChannelByID(cfg *config.Config, id string) (config.Channel, bool) {
	for _, ch := range cfg.Channels {
		if ch.ID == id && ch.Enabled {
			return ch, true
		}
	}
	return config.Channel{}, false
}

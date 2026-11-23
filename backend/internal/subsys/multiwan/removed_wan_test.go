package multiwan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestRemovedWANDoesNotRestoreSuppressedRoute(t *testing.T) {
	for _, operation := range []string{"apply", "tick"} {
		for _, state := range []string{"removed", "disabled", "enabled"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				r := &fakeRunner{}
				c := New(r, t.TempDir(), testLogger{})
				c.suppressed = map[string]string{"old": "default via 192.0.2.1 dev wan0 metric 100"}
				if err := c.save(); err != nil {
					t.Fatal(err)
				}
				cfg := config.Default()
				cfg.Interfaces = []config.Interface{{ID: "i", Name: "wan0"}}
				if state != "removed" {
					cfg.WANs = []config.WAN{{ID: "old", Interface: "i", Enabled: state == "enabled", Proto: "static"}}
				}
				for repeat := 0; repeat < 2; repeat++ {
					if operation == "apply" {
						if err := c.Apply(context.Background(), cfg); err != nil {
							t.Fatal(err)
						}
					} else {
						c.tick(context.Background(), cfg)
					}
					if (r.route != "") != (state == "enabled") {
						t.Fatalf("route=%q state=%s", r.route, state)
					}
					if len(c.suppressed) != 0 {
						t.Fatal(c.suppressed)
					}
					if _, err := os.Stat(c.StatePath); !os.IsNotExist(err) {
						t.Fatalf("snapshot remains: %v", err)
					}
				}
				restores := 0
				for _, cmd := range r.commands {
					if strings.Contains(cmd, "route replace default") {
						restores++
					}
				}
				want := 0
				if state == "enabled" {
					want = 1
				}
				if restores != want {
					t.Fatalf("restores=%d", restores)
				}
			})
		}
	}
}
func BenchmarkRemovedWANApply(b *testing.B) {
	for _, n := range []int{8, 128} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := &fakeRunner{}
			c := New(r, b.TempDir(), testLogger{})
			cfg := config.Default()
			b.ReportAllocs()
			for b.Loop() {
				r.commands = nil
				r.route = ""
				c.suppressed = map[string]string{}
				for i := 0; i < n; i++ {
					c.suppressed[fmt.Sprint(i)] = "default via 192.0.2.1 dev wan0 metric 100"
				}
				if err := c.save(); err != nil {
					b.Fatal(err)
				}
				if err := c.Apply(context.Background(), cfg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type restoreFailureRunner struct {
	fakeRunner
	fail bool
}

func (r *restoreFailureRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if r.fail && strings.Contains(strings.Join(args, " "), "route replace default") {
		return "", fmt.Errorf("injected restore error")
	}
	return r.fakeRunner.Run(ctx, name, args...)
}
func TestRetainedWANRestoreFailureRetries(t *testing.T) {
	for _, operation := range []string{"apply", "tick"} {
		t.Run(operation, func(t *testing.T) {
			r := &restoreFailureRunner{fail: true}
			c := New(r, t.TempDir(), testLogger{})
			c.suppressed = map[string]string{"keep": "default via 192.0.2.1 dev wan0 metric 100"}
			if err := c.save(); err != nil {
				t.Fatal(err)
			}
			cfg := config.Default()
			cfg.Interfaces = []config.Interface{{ID: "i", Name: "wan0"}}
			cfg.WANs = []config.WAN{{ID: "keep", Interface: "i", Enabled: true, Proto: "static"}}
			for range 2 {
				if operation == "apply" {
					if err := c.Apply(context.Background(), cfg); err == nil {
						t.Fatal("restore failure hidden")
					}
				} else {
					c.tick(context.Background(), cfg)
				}
				if len(c.suppressed) != 1 || r.route != "" {
					t.Fatal("lost retry state")
				}
				if saved, err := readSuppressed(c.StatePath); err != nil || len(saved) != 1 {
					t.Fatalf("saved=%v err=%v", saved, err)
				}
			}
			r.fail = false
			if operation == "apply" {
				if err := c.Apply(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
			} else {
				c.tick(context.Background(), cfg)
			}
			if len(c.suppressed) != 0 || r.route == "" {
				t.Fatal("retry did not restore")
			}
		})
	}
}

func BenchmarkSuppressedIdleTick(b *testing.B) {
	for _, n := range []int{8, 128} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := New(&fakeRunner{}, b.TempDir(), testLogger{})
			c.states = map[string]*linkState{}
			c.knownRoutes = map[string]string{}
			c.suppressed = map[string]string{"0": "default dev wan0"}
			cfg := config.Default()
			cfg.MultiWAN.Enabled = true
			cfg.MultiWAN.Mode = "failover"
			for i := 0; i < n; i++ {
				id := fmt.Sprint(i)
				cfg.WANs = append(cfg.WANs, config.WAN{ID: id, Enabled: true, Proto: "static", Probe: config.Probe{Enabled: true}})
				c.states[id] = &linkState{Next: time.Now().Add(time.Hour)}
			}
			b.ReportAllocs()
			for b.Loop() {
				c.tick(context.Background(), cfg)
			}
		})
	}
}

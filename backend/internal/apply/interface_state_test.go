package apply

import (
	"context"
	"fmt"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestEngineAppliesEffectiveInterfacesAndRetainsDesired(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "p", Name: "eth0", Type: "physical", Enabled: false}}
	c.WANs = []config.WAN{{ID: "w", Interface: "p", Enabled: true, Proto: "dhcp", Metric: 10}}
	calls := 0
	e := newTestEngine(t, &testSubsystem{apply: func(_ context.Context, r *config.Config) error {
		calls++
		if r.WANs[0].Enabled {
			t.Fatal("WAN overrides disabled port")
		}
		return nil
	}})
	if _, err := e.Apply(context.Background(), c, 1, false); err != nil {
		t.Fatal(err)
	}
	if err := e.RecoverStartupConnectivity(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !c.WANs[0].Enabled {
		t.Fatal("desired state changed or recovery omitted")
	}
}

func TestApplyRuntimeSnapshotLifetime(t *testing.T) {
	cfg := validConfig("router")
	cfg.Interfaces = []config.Interface{{ID: "p", Name: "eth0", Type: "physical"}}
	cfg.WANs = []config.WAN{{ID: "w", Interface: "p", Enabled: true, Proto: "dhcp", Metric: 10}}
	e := NewEngine(testLogger{}, false)
	var planned, prior *config.Config
	s := flexibleSubsystem{name: "interfaces",
		plan: func(_, next *config.Config) ([]Action, error) { planned = next; return nil, nil },
	}
	check := func(_ context.Context, c *config.Config) error {
		if c != planned || c == cfg || c.WANs[0].Enabled != cfg.Interfaces[0].Enabled {
			t.Fatal("phase did not receive the planned effective network")
		}
		return nil
	}
	s.apply, s.health = check, check
	if err := e.Register(s); err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		next := *cfg
		next.Interfaces = []config.Interface{cfg.Interfaces[0]}
		next.Interfaces[0].Enabled = enabled
		cfg = &next
		if _, err := e.Apply(context.Background(), cfg, 1, false); err != nil {
			t.Fatal(err)
		}
		if e.Current() != cfg || !cfg.WANs[0].Enabled || planned == prior {
			t.Fatal("desired state or snapshot lifetime changed")
		}
		prior = planned
	}
}

func BenchmarkApplyNetworkSnapshot(b *testing.B) {
	for _, n := range []int{32, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := validConfig("router")
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("eth%d", i)
				cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: name, Name: name, Type: "physical", Enabled: true})
			}
			next := *cfg
			next.System.Hostname = "next"
			configs := [2]*config.Config{cfg, &next}
			e := NewEngine(testLogger{}, false)
			if err := e.Register(&testSubsystem{}); err != nil {
				b.Fatal(err)
			}
			index := 0
			b.ReportAllocs()
			for b.Loop() {
				if _, err := e.Apply(context.Background(), configs[index], 1, false); err != nil {
					b.Fatal(err)
				}
				index = 1 - index
			}
		})
	}
}

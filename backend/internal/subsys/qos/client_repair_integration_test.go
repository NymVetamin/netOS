//go:build linux

package qos

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type rateCountingRunner struct {
	system.Runner
	qdiscDeletes, classChanges, filterChanges int
	failClassChange                           bool
}

func (r *rateCountingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "tc" && len(args) > 1 {
		if args[0] == "qdisc" && args[1] == "del" {
			r.qdiscDeletes++
		}
		if args[0] == "class" && args[1] == "change" {
			r.classChanges++
			if r.failClassChange {
				return "", errors.New("injected class change failure")
			}
		}
		if args[0] == "filter" && args[1] == "replace" {
			r.filterChanges++
		}
	}
	return r.Runner.Run(ctx, name, args...)
}

func TestIntegrationClientRateAndCeilRepair(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("root and isolated namespace required")
	}
	self, e1 := os.Readlink("/proc/self/ns/net")
	init, e2 := os.Readlink("/proc/1/ns/net")
	if e1 != nil || e2 != nil || self == init {
		t.Fatal("refusing host namespace")
	}
	ctx := context.Background()
	r := system.NewExec()
	if _, err := r.Run(ctx, "ip", "link", "add", "qos-repair0", "type", "veth", "peer", "name", "qos-repair1"); err != nil {
		t.Fatal(err)
	}
	s := New(r, t.TempDir())
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "qos-repair0", Type: "physical", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Interface: "lan", Enabled: true}}
	cfg.Clients = []config.Client{{ID: "client", MAC: "02:00:00:00:00:01", Network: "home", DownKbit: 5000, UpKbit: 1000}}
	cfg.Clients = append(cfg.Clients, config.Client{ID: "other", MAC: "02:00:00:00:00:02", Network: "home", DownKbit: 7000, UpKbit: 2000})
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	counted := &rateCountingRunner{Runner: r}
	s.Runner = counted
	cfg.Clients[0].DownKbit = 6000
	cfg.Clients[0].UpKbit = 1500
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if counted.qdiscDeletes != 0 || counted.classChanges != 1 || counted.filterChanges != 1 {
		t.Fatalf("rate update rebuilt queues: %+v", counted)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if counted.classChanges != 1 || counted.filterChanges != 1 {
		t.Fatal("unchanged apply mutated rates")
	}
	counted.failClassChange = true
	cfg.Clients[0].DownKbit = 6500
	if err := s.Apply(ctx, cfg); err == nil {
		t.Fatal("class change error swallowed")
	}
	if counted.qdiscDeletes != 0 {
		t.Fatal("class change failure triggered destructive fallback")
	}
	counted.failClassChange = false
	cfg.Clients[0].DownKbit = 5000
	cfg.Clients[0].UpKbit = 1000
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	for _, rates := range [][2]string{{"5000kbit", "9000kbit"}, {"4000kbit", "5000kbit"}} {
		if _, err := r.Run(ctx, "tc", "class", "change", "dev", "qos-repair0", "parent", "1:1", "classid", "1:10", "htb", "rate", rates[0], "ceil", rates[1], "burst", "32k"); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, cfg); err == nil {
			t.Fatal("accepted changed rate/ceil")
		}
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	if counted.qdiscDeletes != 0 {
		t.Fatal("rate repair recreated shared queues")
	}
	if _, err := r.Run(ctx, "tc", "filter", "del", "dev", "qos-repair0", "parent", "1:", "pref", "100"); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if counted.qdiscDeletes == 0 {
		t.Fatal("changed topology did not use repair path")
	}
	cfg.Clients = nil
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}

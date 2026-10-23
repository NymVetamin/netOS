//go:build linux

package qos

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type rateCountingRunner struct {
	system.Runner
	qdiscDeletes, classChanges, filterChanges int
	failClassChange                           bool
	failFilterChange                          bool
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
			if r.failFilterChange {
				return "", errors.New("injected filter change failure")
			}
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
	for _, name := range []string{"qos-repair0", "qos-repair1"} {
		if _, err := r.Run(ctx, "ip", "link", "set", "dev", name, "up"); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "qos-repair0", Type: "physical", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Interface: "lan", RouterAddress: "192.0.2.1/24", Enabled: true}}
	cfg.Clients = []config.Client{{ID: "client", MAC: "02:00:00:00:00:01", Network: "home", DownKbit: 5000, UpKbit: 1000}}
	cfg.Clients = append(cfg.Clients, config.Client{ID: "other", MAC: "02:00:00:00:00:02", Network: "home", DownKbit: 7000, UpKbit: 2000})
	planCtx := apply.WithManagementConnection(ctx, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
	empty := *cfg
	empty.Clients = nil
	if _, err := r.Run(ctx, "ip", "neigh", "replace", "192.0.2.2", "lladdr", "02:00:00:00:00:99", "nud", "permanent", "dev", "qos-repair0"); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.PlanContext(planCtx, &empty, cfg); err != nil || len(actions) != 1 || apply.NeedsConfirmation(actions) {
		out, _ := r.Run(ctx, "tc", "-j", "qdisc", "show", "dev", "qos-repair0")
		t.Logf("initial qdisc %s; admin %q; health %v", out, s.managementMAC(planCtx, cfg), s.Health(ctx, &empty))
		t.Fatalf("first limit plan: %v %v", actions, err)
	}
	if _, err := r.Run(ctx, "ip", "neigh", "replace", "192.0.2.2", "lladdr", cfg.Clients[0].MAC, "nud", "permanent", "dev", "qos-repair0"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]*config.Config{{&empty, cfg}, {cfg, &empty}} {
		if actions, err := s.PlanContext(planCtx, pair[0], pair[1]); err != nil || !apply.NeedsConfirmation(actions) {
			t.Fatalf("administrator limit lifecycle lost confirmation: %v %v", actions, err)
		}
	}
	if _, err := r.Run(ctx, "ip", "neigh", "replace", "192.0.2.2", "lladdr", "02:00:00:00:00:99", "nud", "permanent", "dev", "qos-repair0"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(ctx, "tc", "qdisc", "add", "dev", "qos-repair0", "clsact"); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.PlanContext(planCtx, &empty, cfg); err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("foreign qdisc ignored: %v %v", actions, err)
	}
	if _, err := r.Run(ctx, "tc", "qdisc", "del", "dev", "qos-repair0", "clsact"); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	counted := &rateCountingRunner{Runner: r}
	s.Runner = counted
	old := *cfg
	old.Clients = append([]config.Client(nil), cfg.Clients...)
	cfg.Clients[0].DownKbit = 6000
	cfg.Clients[0].UpKbit = 1500
	for _, tc := range []struct {
		mac  string
		safe bool
	}{{"02:00:00:00:00:99", true}, {"02:00:00:00:00:01", false}} {
		if _, err := r.Run(ctx, "ip", "neigh", "replace", "192.0.2.2", "lladdr", tc.mac, "nud", "permanent", "dev", "qos-repair0"); err != nil {
			t.Fatal(err)
		}
		actions, err := s.PlanContext(planCtx, &old, cfg)
		if err != nil || len(actions) != 1 || (!apply.NeedsConfirmation(actions)) != tc.safe {
			t.Fatalf("rate plan safe=%v: %v %v", tc.safe, actions, err)
		}
	}
	if actions, err := s.Plan(&old, cfg); err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("unknown management path: %v %v", actions, err)
	}
	if counted.classChanges != 0 || counted.filterChanges != 0 || counted.qdiscDeletes != 0 {
		t.Fatal("preview mutated queues")
	}
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
	if _, err := r.Run(ctx, "ip", "neigh", "replace", "192.0.2.2", "lladdr", "02:00:00:00:00:99", "nud", "permanent", "dev", "qos-repair0"); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.PlanContext(planCtx, cfg, &empty); err != nil || len(actions) != 1 || apply.NeedsConfirmation(actions) {
		t.Fatalf("final removal plan: %v %v", actions, err)
	}
	cfg.Clients = nil
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Clients = []config.Client{{ID: "upload", MAC: "02:00:00:00:00:01", Network: "home", UpKbit: 1000}}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	old = *cfg
	old.Clients = append([]config.Client(nil), cfg.Clients...)
	cfg.Clients[0].UpKbit = 2000
	for _, tc := range []struct {
		mac  string
		safe bool
	}{{"02:00:00:00:00:99", true}, {"02:00:00:00:00:01", false}} {
		if _, err := r.Run(ctx, "ip", "neigh", "replace", "192.0.2.2", "lladdr", tc.mac, "nud", "permanent", "dev", "qos-repair0"); err != nil {
			t.Fatal(err)
		}
		actions, err := s.PlanContext(planCtx, &old, cfg)
		if err != nil || len(actions) != 1 || !apply.NeedsConfirmation(actions) != tc.safe {
			t.Fatalf("upload-only safe=%v actions=%v err=%v", tc.safe, actions, err)
		}
	}
	if actions, err := s.Plan(&old, cfg); err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("upload-only unknown path: %v %v", actions, err)
	}
	counted.qdiscDeletes = 0
	counted.failFilterChange = true
	if err := s.Apply(ctx, cfg); err == nil {
		t.Fatal("upload failure swallowed")
	}
	if counted.qdiscDeletes != 0 {
		t.Fatal("upload failure rebuilt queues")
	}
	counted.failFilterChange = false
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if counted.qdiscDeletes != 0 {
		t.Fatal("upload retry rebuilt queues")
	}
	cfg.Clients = nil
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}

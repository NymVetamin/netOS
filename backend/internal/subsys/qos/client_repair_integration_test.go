//go:build linux

package qos

import (
	"context"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

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
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
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
	cfg.Clients = nil
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}

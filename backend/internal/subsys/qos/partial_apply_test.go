package qos

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

var errSecondQueue = errors.New("injected HTB failure")

type partialApplyRunner struct {
	system.Runner
	failDevice   string
	failed       bool
	cleanupCalls int
}

func (r *partialApplyRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "tc" && len(args) >= 5 && args[0] == "qdisc" && args[1] == "replace" && args[3] == r.failDevice && args[4] == "root" {
		r.failed = true
		return "", errSecondQueue
	}
	if r.failed && name == "tc" {
		r.cleanupCalls++
	}
	return r.Runner.Run(ctx, name, args...)
}

func partialClientConfig(names []string) *config.Config {
	cfg := config.Default()
	for i, name := range names {
		cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: name, Name: name, Enabled: true})
		cfg.Networks = append(cfg.Networks, config.Network{ID: name, Interface: name, Enabled: true})
		cfg.Clients = append(cfg.Clients, config.Client{Network: name, MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256), DownKbit: 100})
	}
	return cfg
}

func TestPartialClientApplyCleanup(t *testing.T) {
	for _, count := range []int{2, 128} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			names := make([]string, count)
			fake := &fakeRunner{links: map[string]bool{}}
			for i := range names {
				names[i] = fmt.Sprintf("lan%03d", i)
				fake.links[names[i]] = true
			}
			r := &partialApplyRunner{Runner: fake, failDevice: names[count-1]}
			s := New(r, t.TempDir())
			ctx := context.Background()
			if err := s.Apply(ctx, partialClientConfig(names)); !errors.Is(err, errSecondQueue) {
				t.Fatal(err)
			}
			if r.cleanupCalls != 3*count {
				t.Fatalf("cleanup commands: %d", r.cleanupCalls)
			}
			for _, name := range names {
				if !fake.cleaned[name] {
					t.Fatalf("residual queue on %s", name)
				}
			}
			old := config.Default()
			if err := s.Apply(ctx, old); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(ctx, old); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPartialClientApplyTracksFailedCleanup(t *testing.T) {
	ctx := context.Background()
	names := []string{"lan0", "lan1", "lan2"}
	fake := &fakeRunner{links: map[string]bool{"lan0": true, "lan1": true, "lan2": true}, outputs: map[string]string{
		"tc qdisc show dev lan0": "qdisc htb 1: root",
	}}
	s := New(&partialApplyRunner{Runner: fake, failDevice: "lan1"}, t.TempDir())
	if err := s.Apply(ctx, partialClientConfig(names)); !errors.Is(err, errSecondQueue) {
		t.Fatal(err)
	}
	owned, err := s.readClientInterfaces()
	if err != nil || len(owned) != 1 || owned[0] != "lan0" {
		t.Fatalf("remaining ownership: %v %v", owned, err)
	}
	if _, touched := fake.cleaned["lan2"]; touched {
		t.Fatal("untouched interface cleaned")
	}
	fake.outputs = nil
	s = New(fake, s.StateDir)
	if err := s.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	owned, err = s.readClientInterfaces()
	if err != nil || len(owned) != 0 {
		t.Fatalf("ownership after retry: %v %v", owned, err)
	}
}

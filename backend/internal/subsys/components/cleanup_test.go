package components

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type ipsetRemovalRunner struct {
	installed bool
	purges    int
}

func (r *ipsetRemovalRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "dpkg-query" {
		if args[len(args)-1] == "ipset" && r.installed {
			return "install ok installed", nil
		}
		return "", fmt.Errorf("not installed")
	}
	if name == "apt-get" && strings.Contains(strings.Join(args, " "), "purge") {
		r.installed = false
		r.purges++
	}
	return "", nil
}
func (r *ipsetRemovalRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}
func TestIPSetRemovalWaitsForConsumers(t *testing.T) {
	r := &ipsetRemovalRunner{installed: true}
	s := New(r, testLogger{})
	s.DeferIPSetRemoval = true
	c := config.Default()
	c.Components = nil
	if err := s.Apply(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !r.installed || r.purges != 0 {
		t.Fatal("ipset removed before consumer cleanup")
	}
	cleanup := &Cleanup{Components: s}
	if err := cleanup.Apply(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if r.installed || r.purges != 1 {
		t.Fatal("ipset remains after cleanup")
	}
	if err := cleanup.Apply(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if r.purges != 1 {
		t.Fatal("cleanup not idempotent")
	}
}

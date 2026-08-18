package components

import (
	"context"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type componentRunner struct{ calls int }

func (r *componentRunner) Run(context.Context, string, ...string) (string, error) {
	r.calls++
	return "", nil
}

func (r *componentRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestRemoveDoesNotPurgeEssentialPackage(t *testing.T) {
	runner := &componentRunner{}
	s := New(runner, nil)
	err := s.remove(context.Background(), config.ComponentInfo{
		ID: "qos", Packages: []string{"iproute2"}, Essential: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if runner.calls != 0 {
		t.Fatalf("для базового пакета выполнено %d внешних команд", runner.calls)
	}
}

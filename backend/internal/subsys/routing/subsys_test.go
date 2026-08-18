package routing

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type recordedCommand struct {
	name string
	args []string
}

type recordingRunner struct {
	commands []recordedCommand
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	return "", nil
}

func (r *recordingRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestApplyRoutesOnlyReadsOwnedProtocol(t *testing.T) {
	runner := &recordingRunner{}
	s := New(runner)
	cfg := config.Default()
	cfg.Routing.Static = []config.StaticRoute{{
		ID: "route-1", Enabled: true, Destination: "10.20.0.0/16", Gateway: "192.0.2.1",
	}}

	if err := s.applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("получено команд: %d, ожидалось 2", len(runner.commands))
	}
	show := strings.Join(runner.commands[0].args, " ")
	if show != fmt.Sprintf("-4 route show table all proto %d", config.StaticRouteProto) {
		t.Fatalf("небезопасный запрос маршрутов: ip %s", show)
	}
	add := strings.Join(runner.commands[1].args, " ")
	if strings.Contains(add, "proto static") ||
		!strings.Contains(add, fmt.Sprintf("proto %d", config.StaticRouteProto)) {
		t.Fatalf("маршрут не помечен собственным protocol: ip %s", add)
	}
}

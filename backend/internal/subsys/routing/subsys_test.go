package routing

import (
	"context"
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
	routes   string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	if len(args) >= 3 && args[1] == "route" && args[2] == "show" {
		return r.routes, nil
	}
	return "", nil
}

func (r *recordingRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestApplyRoutesDeletesUnconfiguredStaticRoute(t *testing.T) {
	runner := &recordingRunner{routes: "10.99.0.0/16 via 192.0.2.1 dev eth0 proto static\n"}
	s := New(runner)
	cfg := config.Default()
	if err := s.applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("получено команд: %d, ожидались show и del", len(runner.commands))
	}
	del := strings.Join(runner.commands[1].args, " ")
	if !strings.Contains(del, "route del 10.99.0.0/16") {
		t.Fatalf("неконфигурированный static-маршрут не удалён: ip %s", del)
	}
}

func TestApplyRoutesReconcilesAllStaticRoutes(t *testing.T) {
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
	if show != "-4 route show table all proto static" {
		t.Fatalf("неверный запрос статических маршрутов: ip %s", show)
	}
	add := strings.Join(runner.commands[1].args, " ")
	if !strings.Contains(add, "proto static") {
		t.Fatalf("маршрут не помечен как static: ip %s", add)
	}
}

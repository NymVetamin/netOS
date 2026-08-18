package netiface

import (
	"context"
	"strings"
	"testing"
)

type wanRunner struct {
	commands []string
}

func (r *wanRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if strings.Contains(command, "route show") {
		return "default via 192.0.2.1 dev eth0 proto netos metric 10\n" +
			"default via 198.51.100.1 dev eth1 proto netos metric 20\n", nil
	}
	return "", nil
}

func (r *wanRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestCleanupStaticRoutesKeepsWantedAndDeletesStale(t *testing.T) {
	runner := &wanRunner{}
	s := NewWAN(runner)
	wanted := map[string]bool{wanRouteKey("192.0.2.1", "eth0", 10): true}
	if err := s.cleanupStaticRoutes(context.Background(), wanted); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("команд %d, ожидались show и один del", len(runner.commands))
	}
	if !strings.Contains(runner.commands[1], "route del default via 198.51.100.1 dev eth1") {
		t.Fatalf("удалён не тот маршрут: %s", runner.commands[1])
	}
}

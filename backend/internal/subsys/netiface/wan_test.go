package netiface

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
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

// Нереализованный тип подключения обязан приводить к ошибке. Молчаливый успех
// оставил бы аплинк ненастроенным, а панель отчиталась бы о применении —
// администратор узнал бы о неработающем канале от пользователей.
func TestUnsupportedUplinkProtoFailsLoudly(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "if-wan", Name: "lo", Type: "physical"}}
	cfg.WANs = []config.WAN{{
		ID: "wan1", Name: "Провайдер", Interface: "if-wan",
		Enabled: true, Proto: "выдумка", Metric: 100,
	}}

	s := NewWAN(&wanRunner{})
	err := s.Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "неизвестный тип подключения") {
		t.Fatalf("получено %v, ожидалось сообщение о неизвестном типе подключения", err)
	}
}

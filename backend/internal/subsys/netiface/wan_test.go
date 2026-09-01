package netiface

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type mtuFailRunner struct{}

func (mtuFailRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "ip" && strings.Join(args, " ") == "link set lo mtu 1400" {
		return "", errors.New("operation not supported")
	}
	return "", nil
}

func (r mtuFailRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

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
	s.OwnedRoutePath = filepath.Join(t.TempDir(), "owned-wan-routes.json")
	previous := `[{"gateway":"192.0.2.1","interface":"eth0","metric":10},{"gateway":"198.51.100.1","interface":"eth1","metric":20}]`
	if err := os.WriteFile(s.OwnedRoutePath, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	wanted := []ownedWANRoute{{Gateway: "192.0.2.1", Interface: "eth0", Metric: 10}}
	if err := s.syncStaticRouteOwnership(context.Background(), wanted); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("команд %d, ожидалась одна точная del: %v", len(runner.commands), runner.commands)
	}
	if !strings.Contains(runner.commands[0], "route del default via 198.51.100.1 dev eth1 metric 20 proto 201") {
		t.Fatalf("удалён не тот маршрут: %s", runner.commands[0])
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

func TestWANApplyReportsMTUFailure(t *testing.T) {
	s := NewWAN(mtuFailRunner{})
	err := s.setWANMTU(context.Background(), config.WAN{ID: "wan1", MTU: 1400}, "lo")
	if err == nil || !strings.Contains(err.Error(), "MTU 1400") {
		t.Fatalf("MTU failure was hidden: %v", err)
	}
}

func TestStaticWANOwnershipDeletesOnlyStaleOwnedAddress(t *testing.T) {
	runner := &wanRunner{}
	s := NewWAN(runner)
	s.OwnedAddressPath = filepath.Join(t.TempDir(), "owned-wan-addresses.json")
	previous := `[{"interface":"qa-wan0","address":"192.0.2.2/30"},{"interface":"keep0","address":"198.51.100.2/30"}]`
	if err := os.WriteFile(s.OwnedAddressPath, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	wanted := []ownedWANAddress{{Interface: "keep0", Address: "198.51.100.2/30"}}
	if err := s.syncStaticAddressOwnership(context.Background(), wanted); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "ip addr del 192.0.2.2/30 dev qa-wan0") {
		t.Fatalf("stale owned address was not deleted: %s", joined)
	}
	if strings.Contains(joined, "ip addr del 198.51.100.2/30 dev keep0") {
		t.Fatalf("wanted address was deleted: %s", joined)
	}
	info, err := os.Stat(s.OwnedAddressPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("ownership file mode=%v", info.Mode().Perm())
	}
}

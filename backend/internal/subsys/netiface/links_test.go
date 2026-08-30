package netiface

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// fakeNet подменяет sysfs и /proc/net/vlan каталогом с вымышленными
// интерфейсами: настоящие мосты и VLAN на машине разработчика создавать
// незачем, а на Windows и нечем.
type fakeNet struct{ dir string }

func newFakeNet(t *testing.T, links ...string) *fakeNet {
	t.Helper()
	dir := t.TempDir()
	net := filepath.Join(dir, "net")
	vlan := filepath.Join(dir, "vlan")
	for _, path := range []string{net, vlan} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := &fakeNet{dir: dir}
	for _, l := range links {
		f.add(t, l)
	}

	oldNet, oldVLAN := sysClassNet, procNetVLAN
	sysClassNet, procNetVLAN = net, vlan
	t.Cleanup(func() { sysClassNet, procNetVLAN = oldNet, oldVLAN })
	return f
}

// add создаёт интерфейс: «eth0» — обычный порт, «br1:bridge» — мост,
// «eth0.100:vlan:100:eth0» — VLAN с номером и родителем.
func (f *fakeNet) add(t *testing.T, spec string) {
	t.Helper()
	parts := strings.Split(spec, ":")
	name := parts[0]
	dir := filepath.Join(f.dir, "net", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if len(parts) < 2 {
		return
	}
	switch parts[1] {
	case "bridge":
		if err := os.MkdirAll(filepath.Join(dir, "bridge"), 0o755); err != nil {
			t.Fatal(err)
		}
	case "vlan":
		body := name + "  VID: " + parts[2] + "\t REORDER_HDR: 1\nDevice: " + parts[3] + "\n"
		if err := os.WriteFile(filepath.Join(f.dir, "vlan", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

type linkRunner struct{ commands []string }

func (r *linkRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	return "", nil
}

func (r *linkRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (r *linkRunner) has(substr string) bool {
	for _, c := range r.commands {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func ownedFile(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owned-links")
	body := ""
	for _, n := range names {
		body += n + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// Мост и VLAN, удалённые из панели, обязаны исчезнуть и из системы. Владение
// определяется списком netOS, а не префиксом имени: администратор называет мост
// как хочет, и «br1» под шаблон «br-*» не попадал — удаление до системы не
// доходило вовсе, а ip a продолжал показывать удалённое.
func TestDeletedBridgeAndVLANLeaveTheSystem(t *testing.T) {
	newFakeNet(t, "eth0", "br1:bridge", "eth0.100:vlan:100:eth0", "docker0:bridge")
	runner := &linkRunner{}
	s := &Interfaces{Runner: runner, OwnedPath: ownedFile(t, "br1", "eth0.100")}

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "if-1", Name: "eth0", Type: "physical", Enabled: true}}

	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ip link delete br1", "ip link delete eth0.100"} {
		if !runner.has(want) {
			t.Fatalf("нет команды %q, выполнено: %v", want, runner.commands)
		}
	}
	// Чужой мост не наш: на машине может быть что угодно ещё.
	if runner.has("delete docker0") {
		t.Fatalf("удалён чужой интерфейс: %v", runner.commands)
	}
}

// Список владения переживает перезагрузку: без него удаление из панели опять
// перестало бы доходить до системы.
func TestOwnedListSurvivesRestart(t *testing.T) {
	newFakeNet(t, "eth0")
	path := filepath.Join(t.TempDir(), "owned-links")

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "if-1", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "if-2", Name: "lan", Type: "bridge", Enabled: true},
	}
	first := &Interfaces{Runner: &linkRunner{}, OwnedPath: path}
	if err := first.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	owned := (&Interfaces{OwnedPath: path}).loadOwned()
	if !owned["lan"] {
		t.Fatalf("мост не попал в список владения: %v", owned)
	}
	// Пустому мосту нужен dummy-порт для carrier, и он тоже наш.
	if !owned[dummyNameFor("lan")] {
		t.Fatalf("dummy-порт не попал в список владения: %v", owned)
	}
}

// Смена номера VLAN или родителя обязана доходить до системы. У существующего
// VLAN ни то, ни другое не меняется на ходу: интерфейс пересоздаётся. Иначе
// панель показывала бы одно, а ip a — другое.
func TestChangedVLANIsRecreated(t *testing.T) {
	newFakeNet(t, "eth0", "eth0.100:vlan:100:eth0")
	runner := &linkRunner{}
	s := &Interfaces{Runner: runner, OwnedPath: ownedFile(t, "eth0.100")}

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "if-1", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "if-2", Name: "eth0.100", Type: "vlan", Parent: "if-1", VLANID: 200, Enabled: true},
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !runner.has("ip link delete eth0.100") {
		t.Fatalf("VLAN со сменившимся номером не пересоздан: %v", runner.commands)
	}
	if !runner.has("ip link add link eth0 name eth0.100 type vlan id 200") {
		t.Fatalf("VLAN не создан заново: %v", runner.commands)
	}
}

// Имя, занятое чужим интерфейсом, — повод остановиться и сказать об этом, а не
// молча удалить чужое.
func TestForeignLinkWithSameNameIsNotTouched(t *testing.T) {
	newFakeNet(t, "eth0", "docker0:bridge")
	runner := &linkRunner{}
	s := &Interfaces{Runner: runner, OwnedPath: ownedFile(t)}

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "if-1", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "if-2", Name: "docker0", Type: "vlan", Parent: "if-1", VLANID: 7, Enabled: true},
	}
	err := s.Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "уже занято") {
		t.Fatalf("получено %v, ожидался отказ занять чужое имя", err)
	}
	if runner.has("delete docker0") {
		t.Fatalf("удалён чужой интерфейс: %v", runner.commands)
	}
}

// Порт, выведенный из моста в панели, обязан выйти из него и в системе: иначе
// он остаётся подчинённым, а его собственный адрес не работает.
func TestFormerMemberIsReleased(t *testing.T) {
	f := newFakeNet(t, "eth0", "eth1", "lan:bridge")
	// eth1 подчинён мосту прямо сейчас.
	if err := os.MkdirAll(filepath.Join(f.dir, "net", "lan", "brif", "eth1"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &linkRunner{}
	s := &Interfaces{Runner: runner, OwnedPath: ownedFile(t, "lan")}

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "if-1", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "if-2", Name: "eth1", Type: "physical", Enabled: true},
		{ID: "if-br", Name: "lan", Type: "bridge", Members: []string{"if-1"}, Enabled: true},
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !runner.has("ip link set eth1 nomaster") {
		t.Fatalf("порт остался в мосту: %v", runner.commands)
	}
	if !runner.has("ip link set eth0 master lan") {
		t.Fatalf("выбранный порт в мост не добавлен: %v", runner.commands)
	}
}

// Состав моста и родитель VLAN описаны идентификаторами: команды ip обязаны
// получить имена, иначе в системе не появится ничего.
func TestMembersAndParentAreResolvedToNames(t *testing.T) {
	newFakeNet(t, "eth0", "eth1")
	runner := &linkRunner{}
	s := &Interfaces{Runner: runner, OwnedPath: ownedFile(t)}

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "if-1", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "if-2", Name: "eth1", Type: "physical", Enabled: true},
		{ID: "if-br", Name: "lan", Type: "bridge", Members: []string{"if-2"}, Enabled: true},
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !runner.has("ip link add name lan type bridge") {
		t.Fatalf("мост не создан: %v", runner.commands)
	}
	if runner.has("master if-br") || runner.has("set if-2") {
		t.Fatalf("в команды ip попал идентификатор вместо имени: %v", runner.commands)
	}
}

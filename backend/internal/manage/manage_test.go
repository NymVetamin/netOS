package manage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testManager() (*Manager, *bytes.Buffer) {
	out := &bytes.Buffer{}
	m := New("v1.2.3")
	m.In = strings.NewReader("")
	m.Out, m.Err = out, out
	m.EUID = func() int { return 0 }
	m.Run = func(context.Context, command) error { return nil }
	m.Output = func(context.Context, string, ...string) (string, error) { return "", nil }
	// Ожидание дефолтного маршрута опрашивает таблицу раз в секунду. С живым
	// time.Sleep каждый тест удаления стоил бы два десятка секунд.
	m.Sleep = func(time.Duration) {}
	return m, out
}

// sandbox уводит все пути менеджера во временный каталог. Тесты удаления и
// сброса выполняют настоящие os.Remove, и без этого прогон под root на машине
// разработки снёс бы установленный там netOS.
func sandbox(t *testing.T, m *Manager) {
	t.Helper()
	root := t.TempDir()
	m.Root = root
	m.StateDir = filepath.Join(root, "var/lib/netos")
	m.ConfigDir = filepath.Join(root, "etc/netos")
	m.LogDir = filepath.Join(root, "var/log/netos")
	m.BackupDir = filepath.Join(root, "var/backups/netos")
	m.Binary = filepath.Join(root, "usr/local/bin/netosd")
	m.CLI = filepath.Join(root, "usr/local/bin/netos")
	m.Unit = filepath.Join(root, "etc/systemd/system/netosd.service")
}

func TestHelpUsesPublicNetosCommands(t *testing.T) {
	m, out := testManager()
	if err := m.Execute(context.Background(), []string{"help"}); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"netos update", "netos reinstall", "netos reset", "netos uninstall"} {
		if !strings.Contains(out.String(), command) {
			t.Fatalf("справка не содержит %q", command)
		}
	}
}

func TestVersion(t *testing.T) {
	m, out := testManager()
	if err := m.Execute(context.Background(), []string{"version"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "netOS v1.2.3\n" {
		t.Fatalf("неожиданный вывод: %q", out.String())
	}
}

func TestMutationRequiresRoot(t *testing.T) {
	m, _ := testManager()
	m.EUID = func() int { return 1000 }
	if err := m.Execute(context.Background(), []string{"update"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("update без root вернул %v", err)
	}
}

func TestResetWithoutConfirmationDoesNothing(t *testing.T) {
	m, out := testManager()
	calls := 0
	m.Run = func(context.Context, command) error { calls++; return nil }
	if err := m.Execute(context.Background(), []string{"reset"}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("после отказа выполнено команд: %d", calls)
	}
	if !strings.Contains(out.String(), "Отменено") {
		t.Fatalf("нет сообщения об отмене: %q", out.String())
	}
}

func TestVersionArgumentRejectsShellSyntax(t *testing.T) {
	if _, err := positionalVersion([]string{"v1.0;reboot"}); err == nil {
		t.Fatal("опасная версия принята")
	}
}

func TestUpdatePassesRequestedVersionToInstaller(t *testing.T) {
	m, _ := testManager()
	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	if err := m.Execute(context.Background(), []string{"update", "v1.2.4"}); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || commands[1].name != "bash" {
		t.Fatalf("неожиданные команды: %#v", commands)
	}
	if !contains(commands[1].env, "NETOS_VERSION=v1.2.4") {
		t.Fatalf("версия не передана установщику: %#v", commands[1].env)
	}
}

// reinstall — синоним update, и это должно оставаться проверяемым фактом,
// а не обещанием в тексте справки.
func TestReinstallBehavesLikeUpdate(t *testing.T) {
	m, _ := testManager()
	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	if err := m.Execute(context.Background(), []string{"reinstall", "v1.2.4"}); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || commands[1].name != "bash" ||
		!contains(commands[1].env, "NETOS_VERSION=v1.2.4") {
		t.Fatalf("reinstall расходится с update: %#v", commands)
	}
}

// Сборка из исходников тянет Go и компилирует встроенный SQLite: на роутере
// это десятки минут и уход в своп. Обновление не имеет права свернуть туда
// само — администратор просил обновиться, а не запускать сборку на работающем
// роутере.
func TestUpdateRefusesMissingReleaseInsteadOfBuildingFromSource(t *testing.T) {
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("not found")
	}
	var started bool
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "bash" {
			started = true
		}
		return nil
	}
	err := m.Execute(context.Background(), []string{"update", "v9.9.9"})
	if err == nil {
		t.Fatal("обновление на несуществующий релиз прошло молча")
	}
	if !strings.Contains(err.Error(), "NETOS_FROM_SOURCE=1") {
		t.Fatalf("отказ не объясняет, как собрать из исходников: %v", err)
	}
	if started {
		t.Fatal("установщик запущен, хотя релиза нет")
	}
}

// Явно запрошенная сборка из исходников должна доходить до установщика.
func TestUpdateBuildsFromSourceWhenAskedExplicitly(t *testing.T) {
	t.Setenv("NETOS_FROM_SOURCE", "1")
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("not found")
	}
	var installer command
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "bash" {
			installer = spec
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"update"}); err != nil {
		t.Fatal(err)
	}
	if !contains(installer.env, "NETOS_FROM_SOURCE=1") {
		t.Fatalf("сборка из исходников не включена: %#v", installer.env)
	}
}

// Установщик берётся из того же тега, что и бинарник: иначе указанная версия
// ставилась бы сегодняшним скриптом с master.
func TestUpdateTakesInstallerFromRequestedTag(t *testing.T) {
	m, _ := testManager()
	var fetched []string
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "curl" {
			fetched = append(fetched, spec.args[len(spec.args)-1])
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"update", "v0.05"}); err != nil {
		t.Fatal(err)
	}
	want := "https://raw.githubusercontent.com/NymVetamin/netOS/v0.05/install.sh"
	if !contains(fetched, want) {
		t.Fatalf("установщик взят не из тега: %v", fetched)
	}
}

func TestRemovePolicyRulesOnlyTouchesNetOSRange(t *testing.T) {
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) {
		return "0: from all lookup local\n20100: from 10.0.0.0/8 lookup vpn\n32766: from all lookup main\n", nil
	}
	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	m.removePolicyRules(context.Background())
	if len(commands) != 1 || !contains(commands[0].args, "20100") {
		t.Fatalf("удалены неверные правила: %#v", commands)
	}
}

// systemctl stop отдаёт код 5 на незагруженный юнит. Если считать это ошибкой,
// удаление после однажды прерванной попытки уже никогда не доработает.
func TestUninstallProceedsWhenUnitIsNotLoaded(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		if spec.name == "systemctl" && len(spec.args) > 0 && spec.args[0] == "stop" {
			return errors.New("Unit netosd.service not loaded")
		}
		return nil
	}
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "unknown\n", errors.New("exit status 4")
		}
		return "", nil
	}
	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatalf("удаление прервалось на незагруженном юните: %v", err)
	}
	var cleared bool
	for _, c := range commands {
		if c.name == "iptables-restore" {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("удаление не дошло до очистки правил: %#v", commands)
	}
}

func TestStopDaemonReportsRealFailure(t *testing.T) {
	m, _ := testManager()
	m.Run = func(context.Context, command) error { return errors.New("job failed") }
	m.Output = func(context.Context, string, ...string) (string, error) { return "active\n", nil }
	if err := m.stopDaemon(context.Background()); err == nil {
		t.Fatal("остановка работающей службы провалилась, но ошибка потеряна")
	}
}

func TestLogsRequireRoot(t *testing.T) {
	m, _ := testManager()
	m.EUID = func() int { return 1000 }
	if err := m.Execute(context.Background(), []string{"logs"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("logs без root вернул %v", err)
	}
}

// Удаление обязано возвращать машину в исходное состояние. Оставленное
// описание сегментов пережило бы netOS: система продолжала бы создавать
// бриджи и адреса, которых больше никто не обслуживает.
func TestUninstallRemovesGeneratedNetworkConfig(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	m.Run = func(context.Context, command) error { return nil }

	ifupdown := filepath.Join(m.Root, "etc/network/interfaces.d/netos.conf")
	networkd := filepath.Join(m.Root, "etc/systemd/network/05-netos-br-lan.network")
	foreign := filepath.Join(m.Root, "etc/systemd/network/10-all.network")
	for _, path := range []string{ifupdown, networkd, foreign} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ifupdown, networkd} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("после удаления остался %s", path)
		}
	}
	// Чужие файлы не наши, и трогать их нельзя.
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("удалён чужой файл конфигурации сети: %v", err)
	}
}

// Резолвер роутера netOS забирает себе, а значит обязан отдать: машина после
// удаления должна разрешать имена ровно так же, как до установки. Память об
// исходном состоянии лежит в StateDir, который удаление стирает, — восстановить
// файл позже будет неоткуда.
func TestUninstallGivesResolvConfBackToSystem(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	var commands []string
	m.Run = func(_ context.Context, c command) error {
		commands = append(commands, c.name+" "+strings.Join(c.args, " "))
		return nil
	}

	resolv := filepath.Join(m.Root, "etc/resolv.conf")
	state := filepath.Join(m.Root, "var/lib/netos/resolv-conf.state")
	for _, dir := range []string{filepath.Dir(resolv), filepath.Dir(state)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(resolv, []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte(
		`{"kind":"file","content":"nameserver 10.0.0.1\n","resolved_enabled":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("resolv.conf не восстановлен: %v", err)
	}
	if string(content) != "nameserver 10.0.0.1\n" {
		t.Errorf("восстановлено не исходное содержимое: %q", content)
	}
	var revived bool
	for _, c := range commands {
		if strings.Contains(c, "enable --now systemd-resolved.service") {
			revived = true
		}
	}
	if !revived {
		t.Errorf("systemd-resolved не возвращён системе: %v", commands)
	}
}

// Удаление снимает маршруты netOS, но systemd-networkd держит в памяти
// прежнюю конфигурацию линка и сам адресацию не перезапускает. Без явного
// reconfigure машина остаётся с адресом и без пути наружу — на удалённом
// роутере это потеря доступа до перезагрузки.
func TestUninstallHandsInterfacesBackToNetworkManager(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)

	networkd := filepath.Join(m.Root, "etc/systemd/network/05-netos-eth0.network")
	if err := os.MkdirAll(filepath.Dir(networkd), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(networkd, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Линк должен существовать: для удалённых виртуальных интерфейсов
	// reconfigure звать незачем.
	if err := os.MkdirAll(filepath.Join(m.Root, "sys/class/net/eth0"), 0o755); err != nil {
		t.Fatal(err)
	}

	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	// Маршрут виден только до очистки: дальше networkd его не возвращает.
	shown := 0
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "ip" && contains(args, "default") {
			shown++
			if shown == 1 {
				return "default via 45.38.170.1 dev eth0 proto netos metric 100\n", nil
			}
			return "", nil
		}
		return "", nil
	}

	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatal(err)
	}

	var reconfigured, restored bool
	for _, c := range commands {
		if c.name == "networkctl" && len(c.args) == 2 && c.args[0] == "reconfigure" && c.args[1] == "eth0" {
			reconfigured = true
		}
		if c.name == "ip" && contains(c.args, "add") && contains(c.args, "45.38.170.1") {
			restored = true
		}
	}
	if !reconfigured {
		t.Fatalf("интерфейс не возвращён systemd-networkd: %#v", commands)
	}
	if !restored {
		t.Fatalf("дефолтный маршрут не восстановлен, машина осталась без связи: %#v", commands)
	}
}

// Когда штатный менеджер сети маршрут вернул, лезть руками нельзя: чужой
// маршрут поверх своего означал бы дубль и неопределённый выбор канала.
func TestUninstallDoesNotAddRouteWhenNetworkManagerReturnedIt(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)

	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "ip" && contains(args, "default") {
			return "default via 45.38.170.1 dev eth0 proto dhcp\n", nil
		}
		return "", nil
	}

	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatal(err)
	}
	for _, c := range commands {
		if c.name == "ip" && contains(c.args, "add") {
			t.Fatalf("маршрут добавлен вручную, хотя менеджер сети вернул свой: %#v", c)
		}
	}
}

// Компоненты включает администратор, и на машине с одной панелью их юнитов
// нет. Отсутствующий юнит — достигнутая цель, а не сбой: systemctl не должен
// вызываться и пугать администратора пятью отказами подряд.
func TestUninstallSkipsComponentUnitsThatWereNeverInstalled(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)

	installed := filepath.Join(m.Root, "etc/systemd/system/netos-dnsmasq.service")
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	var disabled []string
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "systemctl" && len(spec.args) > 1 && spec.args[0] == "disable" {
			disabled = append(disabled, spec.args[len(spec.args)-1])
		}
		return nil
	}

	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatal(err)
	}
	if !contains(disabled, "netos-dnsmasq.service") {
		t.Fatalf("заведённый юнит компонента не погашен: %v", disabled)
	}
	for _, unit := range []string{"netos-unbound.service", "netos-dnsproxy.service", "netos-kea-dhcp4.service"} {
		if contains(disabled, unit) {
			t.Fatalf("systemctl вызван для юнита, которого нет: %s", unit)
		}
	}
	if strings.Contains(out.String(), "Предупреждение: systemctl") {
		t.Fatalf("удаление пожаловалось на systemctl из-за юнитов, которых нет: %s", out.String())
	}
}

func TestUninstallStopsAndRemovesDynamicNetworkUnits(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	unitDir := filepath.Join(m.Root, "etc/systemd/system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	units := []string{
		"netos-dhcp-test.service", "netos-pppoe-test.service", "netos-l2tp-test.service",
		"netos-openconnect-ch12.service", "netos-xray-ch13.service",
	}
	for _, unit := range units {
		if err := os.WriteFile(filepath.Join(unitDir, unit), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var disabled []string
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "systemctl" && len(spec.args) > 1 && spec.args[0] == "disable" {
			disabled = append(disabled, spec.args[len(spec.args)-1])
		}
		return nil
	}
	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatal(err)
	}
	for _, unit := range units {
		if !contains(disabled, unit) {
			t.Errorf("dynamic unit was not disabled: %s", unit)
		}
		if _, err := os.Stat(filepath.Join(unitDir, unit)); !os.IsNotExist(err) {
			t.Errorf("dynamic unit was not removed: %s (%v)", unit, err)
		}
	}
}

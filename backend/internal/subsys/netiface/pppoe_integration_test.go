//go:build linux

package netiface

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Проверка клиента PPPoE против настоящего концентратора.
//
// Юнит-тесты подтверждают только то, что мы сгенерировали ожидаемый текст.
// Правильность этого текста доказывает лишь pppd, который по нему дозвонился:
// имя опции, которой нет в этой версии, или пропущенный параметр видны только
// в реальном соединении.
//
// Стенд — пара veth: на одном конце pppoe-server, на другом наш клиент.
// Концентратор живёт в отдельном network namespace, и это не украшение: с
// обоими концами veth в одном namespace кадры стадии сессии (0x8864) не
// доходят, discovery проходит, а LCP уже нет.
//
// Тест требует root и пакетов ppp и pppoe, поэтому по умолчанию пропускается и
// запускается явно: NETOS_INTEGRATION=1 go test ./internal/subsys/netiface/ -run PPPoE
const (
	testNetns       = "netos-ppptest"
	testServerIface = "ppptest-srv"
	testClientIface = "ppptest-cli"
	testUser        = "netos-test-user"
	testPassword    = "netos-test-password"
	testServerAddr  = "10.99.77.1"
	testClientAddr  = "10.99.77.2"
	// Метрика заведомо хуже любых боевых маршрутов машины: тестовая сессия не
	// должна перехватить трафик и оборвать управление стендом.
	testMetric = 4000
)

func TestPPPoEDialsUpAgainstRealConcentrator(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("интеграционный тест: NETOS_INTEGRATION=1 и root")
	}
	if os.Geteuid() != 0 {
		t.Skip("нужен root: тест создаёт интерфейсы и запускает pppd")
	}
	for _, bin := range []string{"pppd", "pppoe-server", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s", bin)
		}
	}

	ctx := context.Background()
	runner := system.NewExec()

	ensureServerPlugin(t)
	setupLink(t)
	setupSecrets(t)
	startServer(t)

	w := config.WAN{
		ID: "wan1", Name: "Тестовый провайдер", Interface: "if-wan", Enabled: true,
		Proto: "pppoe", Username: testUser, Password: testPassword, Metric: testMetric,
	}

	// Файл тот же самый, что уйдёт в бой: тест не имеет права звонить копией.
	confPath := t.TempDir() + "/pppoe.conf"
	if err := os.WriteFile(confPath, []byte(renderPPPoEConf(w, testClientIface)), 0o600); err != nil {
		t.Fatal(err)
	}

	client := startClient(t, confPath)

	iface := PPPoEInterface(w.ID)
	if !waitForAddress(t, ctx, runner, iface, 40*time.Second) {
		t.Fatalf("сессия не установилась за 40 с\nжурнал pppd:\n%s", client.String())
	}

	t.Run("интерфейс назван так, как ожидают правила файрволла", func(t *testing.T) {
		if iface != "ppp-wan1" {
			t.Fatalf("имя интерфейса %q", iface)
		}
		out, err := runner.Run(ctx, "ip", "-4", "addr", "show", "dev", iface)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, testClientAddr) {
			t.Fatalf("провайдер выдал не тот адрес:\n%s", out)
		}
	})

	t.Run("маршрут по умолчанию получил заданную метрику", func(t *testing.T) {
		out, err := runner.Run(ctx, "ip", "-4", "route", "show", "default", "dev", iface)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "metric 4000") {
			t.Fatalf("метрика аплинка не применилась, а от неё зависит выбор основного канала:\n%s", out)
		}
	})

	t.Run("IPv6 на сессии не поднят", func(t *testing.T) {
		out, err := runner.Run(ctx, "ip", "-6", "addr", "show", "dev", iface)
		if err != nil {
			// Ядро без IPv6 — подавлять нечего.
			return
		}
		if strings.Contains(out, "inet6") && !strings.Contains(out, "fe80::") {
			t.Fatalf("на сессии поднялся глобальный IPv6, хотя он подавляется:\n%s", out)
		}
	})
}

// Неверный пароль обязан приводить к отказу, а не к молчаливо поднятому
// интерфейсу без связи: иначе проверка после применения пропустит битый
// аплинк и админ узнает о нём от пользователей.
func TestPPPoERejectsWrongPassword(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("интеграционный тест: NETOS_INTEGRATION=1 и root")
	}
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
	for _, bin := range []string{"pppd", "pppoe-server"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s", bin)
		}
	}

	ensureServerPlugin(t)
	setupLink(t)
	setupSecrets(t)
	startServer(t)

	w := config.WAN{
		ID: "wan1", Name: "Тестовый провайдер", Interface: "if-wan", Enabled: true,
		Proto: "pppoe", Username: testUser, Password: "wrong-password", Metric: testMetric,
	}
	confPath := t.TempDir() + "/pppoe.conf"
	if err := os.WriteFile(confPath, []byte(renderPPPoEConf(w, testClientIface)), 0o600); err != nil {
		t.Fatal(err)
	}
	client := startClient(t, confPath)

	ctx := context.Background()
	runner := system.NewExec()
	if waitForAddress(t, ctx, runner, PPPoEInterface(w.ID), 20*time.Second) {
		t.Fatalf("сессия поднялась с неверным паролем\nжурнал pppd:\n%s", client.String())
	}
	if !strings.Contains(client.String(), "authentication failed") &&
		!strings.Contains(client.String(), "Failed to authenticate") &&
		!strings.Contains(client.String(), "PAP authentication failed") {
		t.Logf("журнал pppd (для сведения):\n%s", client.String())
	}
}

// ---------------------------------------------------------------------------

func setupLink(t *testing.T) {
	t.Helper()
	teardownLink()

	mustRun(t, "ip", "netns", "add", testNetns)
	t.Cleanup(teardownLink)

	mustRun(t, "ip", "link", "add", testClientIface, "type", "veth", "peer", "name", testServerIface)
	mustRun(t, "ip", "link", "set", testServerIface, "netns", testNetns)
	mustRun(t, "ip", "link", "set", testClientIface, "up")
	mustRun(t, "ip", "netns", "exec", testNetns, "ip", "link", "set", testServerIface, "up")
	mustRun(t, "ip", "netns", "exec", testNetns, "ip", "link", "set", "lo", "up")
}

func teardownLink() {
	// Процессы концентратора живут внутри namespace и должны уйти вместе с ним.
	if out, err := exec.Command("ip", "netns", "pids", testNetns).Output(); err == nil {
		for _, pid := range strings.Fields(string(out)) {
			_ = exec.Command("kill", pid).Run()
		}
	}
	_ = exec.Command("ip", "netns", "del", testNetns).Run()
	_ = exec.Command("ip", "link", "del", testClientIface).Run()
}

// ensureServerPlugin кладёт симлинк на плагин там, где его ищет pppoe-server.
//
// Это дефект упаковки concentrator-части в Debian: pppoe-server -k запускает
// pppd с путём /etc/ppp/plugins/rp-pppoe.so, которого в дистрибутиве нет.
// Клиента netOS это не касается — он называет плагин по имени, и pppd находит
// его в своём каталоге.
func ensureServerPlugin(t *testing.T) {
	t.Helper()
	const link = "/etc/ppp/plugins/rp-pppoe.so"
	if _, err := os.Stat(link); err == nil {
		return
	}
	matches, err := filepath.Glob("/usr/lib/pppd/*/rp-pppoe.so")
	if err != nil || len(matches) == 0 {
		t.Skip("не найден плагин rp-pppoe.so")
	}
	if err := os.MkdirAll("/etc/ppp/plugins", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(matches[0], link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
}

// setupSecrets кладёт учётные данные для серверной стороны.
//
// Это файл концентратора, а не роутера: сам netOS в /etc/ppp/pap-secrets не
// пишет — его пароль лежит в собственной конфигурации pppd. Прежнее
// содержимое восстанавливается, чтобы стенд не оставлял следов на машине.
func setupSecrets(t *testing.T) {
	t.Helper()
	const path = "/etc/ppp/pap-secrets"
	previous, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	line := testUser + " * " + testPassword + " " + testClientAddr + "\n"
	if err := os.WriteFile(path, append(append([]byte{}, previous...), []byte(line)...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if previous == nil {
			_ = os.Remove(path)
			return
		}
		_ = os.WriteFile(path, previous, 0o600)
	})
}

func startServer(t *testing.T) {
	t.Helper()
	options := t.TempDir() + "/pppoe-server-options"
	// Концентратор требует PAP — иначе тест не проверял бы, что клиент вообще
	// умеет представляться логином и паролем.
	content := "require-pap\nlcp-echo-interval 10\nlcp-echo-failure 3\nnoipv6\n"
	if err := os.WriteFile(options, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ip", "netns", "exec", testNetns, "pppoe-server",
		"-I", testServerIface,
		"-L", testServerAddr,
		"-R", testClientAddr,
		"-N", "1",
		"-O", options,
		"-k")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("не удалось запустить pppoe-server: %v\n%s", err, out)
	}
	// Отдельной уборки не требуется: процессы концентратора живут в namespace
	// и уходят вместе с ним в teardownLink.
}

type logBuffer struct {
	cmd  *exec.Cmd
	sink *strings.Builder
}

func (l *logBuffer) String() string { return l.sink.String() }

func startClient(t *testing.T, confPath string) *logBuffer {
	t.Helper()
	sink := &strings.Builder{}
	cmd := exec.Command("pppd", "file", confPath, "nodetach")
	cmd.Stdout, cmd.Stderr = sink, sink
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return &logBuffer{cmd: cmd, sink: sink}
}

func waitForAddress(t *testing.T, ctx context.Context, runner system.Runner, iface string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if addrs, err := addressesOf(ctx, runner, iface); err == nil && len(addrs) > 0 {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

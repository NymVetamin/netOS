//go:build linux

package netconf

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

// Проверка сгенерированных файлов настоящими ifupdown и systemd-networkd.
//
// Юнит-тесты подтверждают только то, что мы написали ожидаемый текст. Приняли
// ли этот текст сами инструменты — вопрос отдельный: опечатка в имени ключа
// или синтаксис, которого нет в этой версии, видны лишь их разбором.
//
// Имена интерфейсов намеренно не совпадают ни с одним настоящим: тест
// запускается на работающей машине, где systemd-networkd управляет живым
// аплинком, и его конфигурация не должна задеть ничего постороннего.
//
// NETOS_INTEGRATION=1 go test ./internal/subsys/netconf/ -run Integration
const (
	testUplink = "nctest-wan"
	testPort1  = "nctest-p1"
	testPort2  = "nctest-p2"
	testBridge = "nctest-br"
	testVLAN   = "nctest-vl"
)

func integrationConfig() *config.Config {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "if-wan", Name: testUplink, Type: "physical", Enabled: true},
		{ID: "if-p1", Name: testPort1, Type: "physical", Enabled: true},
		{ID: "if-p2", Name: testPort2, Type: "physical", Enabled: true},
		{ID: "if-lan", Name: testBridge, Type: "bridge", Members: []string{"if-p1", "if-p2"}, Enabled: true},
		{ID: "if-guest", Name: testVLAN, Type: "vlan", Parent: "if-lan", VLANID: 20, Enabled: true},
	}
	cfg.Networks = []config.Network{
		{ID: "lan", Name: "LAN", Interface: "if-lan", RouterAddress: "192.168.77.1/24", Enabled: true},
		{ID: "guest", Name: "Гости", Interface: "if-guest", RouterAddress: "192.168.78.1/24", Enabled: true},
	}
	cfg.WANs = []config.WAN{
		{ID: "wan1", Name: "Провайдер", Interface: "if-wan", Enabled: true, Proto: "dhcp", Metric: 100},
	}
	return cfg
}

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("интеграционный тест: NETOS_INTEGRATION=1 и root")
	}
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
}

// ifupdown разбирает наш файл и соглашается поднять по нему сеть.
//
// ifquery читает описание, ifup --no-act проходит весь путь до выполнения и
// печатает команды, ничего не применяя: настоящая проверка синтаксиса без
// риска для сети машины.
func TestIntegrationIfupdownAcceptsGeneratedFile(t *testing.T) {
	requireIntegration(t)
	for _, bin := range []string{"ifquery", "ifup"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s — установите пакет ifupdown", bin)
		}
	}

	path := filepath.Join(t.TempDir(), "netos.conf")
	if err := os.WriteFile(path, []byte(renderIfupdown(integrationConfig())), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("ifquery", "-i", path, "--list", "--allow", "auto").CombinedOutput()
	if err != nil {
		t.Fatalf("ifquery не разобрал файл: %v\n%s", err, out)
	}
	listed := strings.Fields(string(out))
	// Сегменты обязаны подниматься при загрузке, порты бриджа — нет: их
	// поднимает сам бридж.
	for _, want := range []string{testBridge, testVLAN, testUplink} {
		if !contains(listed, want) {
			t.Fatalf("%s не поднимается автоматически, поднимаются: %v", want, listed)
		}
	}
	for _, unwanted := range []string{testPort1, testPort2} {
		if contains(listed, unwanted) {
			t.Fatalf("порт бриджа %s поднимается отдельно, будет гонка: %v", unwanted, listed)
		}
	}

	for _, iface := range []string{testBridge, testVLAN, testUplink} {
		out, err := exec.Command("ifup", "--no-act", "-i", path, iface).CombinedOutput()
		if err != nil {
			t.Fatalf("ifup не принял описание %s: %v\n%s", iface, err, out)
		}
		if iface == testBridge && !strings.Contains(string(out), "192.168.77.1") {
			t.Fatalf("ifupdown не назначит адрес сегмента:\n%s", out)
		}
	}
}

// systemd-networkd принимает наши файлы и действительно собирает по ним сеть.
//
// Проверяем на dummy-интерфейсах: они создаются здесь же и не пересекаются с
// настоящими, поэтому живой аплинк машины остаётся нетронутым.
func TestIntegrationNetworkdAppliesGeneratedFiles(t *testing.T) {
	requireIntegration(t)
	if _, err := exec.LookPath("networkctl"); err != nil {
		t.Skip("нет networkctl")
	}
	if !unitActive("systemd-networkd.service") {
		t.Skip("systemd-networkd не запущен")
	}

	// Физические порты изображаем dummy-устройствами: бридж и VLAN networkd
	// создаст сам по .netdev.
	for _, name := range []string{testUplink, testPort1, testPort2} {
		_ = exec.Command("ip", "link", "del", name).Run()
		if out, err := exec.Command("ip", "link", "add", name, "type", "dummy").CombinedOutput(); err != nil {
			t.Fatalf("не удалось создать %s: %v\n%s", name, err, out)
		}
	}
	t.Cleanup(func() {
		for _, name := range []string{testVLAN, testBridge, testUplink, testPort1, testPort2} {
			_ = exec.Command("ip", "link", "del", name).Run()
		}
	})

	files := renderNetworkd(integrationConfig())
	var written []string
	for name, content := range files {
		path := filepath.Join(networkdDir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		written = append(written, path)
	}
	t.Cleanup(func() {
		for _, path := range written {
			_ = os.Remove(path)
		}
		_ = exec.Command("networkctl", "reload").Run()
	})

	if out, err := exec.Command("networkctl", "reload").CombinedOutput(); err != nil {
		t.Fatalf("networkd не перечитал конфигурацию: %v\n%s", err, out)
	}

	// Разбор файлов networkd сообщает в журнал; молчаливого отказа быть не
	// должно, поэтому проверяем и результат, и отсутствие жалоб.
	if !waitFor(t, 20*time.Second, func() bool {
		return linkExists(testBridge) && linkExists(testVLAN) && hasAddress(testBridge, "192.168.77.1/24")
	}) {
		t.Fatalf("networkd не собрал сеть по нашим файлам\n%s", networkdComplaints())
	}

	if !hasAddress(testVLAN, "192.168.78.1/24") {
		t.Fatalf("VLAN не получил адрес сегмента\n%s", networkdComplaints())
	}
	if master := linkMaster(testPort1); master != testBridge {
		t.Fatalf("порт %s подчинён %q, а не бриджу", testPort1, master)
	}
	// Аплинку адрес назначает netOS; networkd не должен ни выдать свой, ни
	// снять чужой.
	if addrs := addressesOf(testUplink); len(addrs) > 0 {
		t.Fatalf("networkd назначил аплинку адрес в обход netOS: %v", addrs)
	}
	if complaints := networkdComplaints(); complaints != "" {
		t.Fatalf("networkd пожаловался на наши файлы:\n%s", complaints)
	}
}

// ---------------------------------------------------------------------------

func unitActive(unit string) bool {
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}

func linkExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

func linkMaster(name string) string {
	target, err := os.Readlink("/sys/class/net/" + name + "/master")
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func addressesOf(name string) []string {
	out, err := exec.Command("ip", "-4", "-brief", "addr", "show", "dev", name).Output()
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return nil
	}
	return fields[2:]
}

func hasAddress(name, address string) bool {
	return contains(addressesOf(name), address)
}

// networkdComplaints собирает свежие жалобы networkd именно на разбор наших
// файлов.
//
// Упоминание нашего файла само по себе жалобой не является: networkd пишет в
// журнал безобидное «Found matching .network file, based on potentially
// unpredictable interface name» на каждое сопоставление по имени. Ищем только
// то, что говорит о непонятой конфигурации.
func networkdComplaints() string {
	out, err := exec.Command("journalctl", "-u", "systemd-networkd",
		"--since", "-1 min", "--no-pager", "-p", "warning").Output()
	if err != nil {
		return ""
	}
	problems := []string{"Unknown key", "Failed to parse", "Invalid ", "Ignoring "}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		for _, problem := range problems {
			if strings.Contains(line, problem) {
				lines = append(lines, line)
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

func waitFor(t *testing.T, timeout time.Duration, ready func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// Передача управления от systemd-networkd к netOS.
//
// Проверяем два свойства, каждое из которых было нарушено и стоило поломки.
// Первое: адрес, назначенный netOS, обязан пережить передачу — иначе аплинк
// остаётся без адреса, а на удалённой машине это потеря доступа. Второе: линк
// обязан остаться видимым для networkd — со скрытым линком
// systemd-networkd-wait-online ждёт впустую весь таймаут и добавляет к загрузке
// две минуты.
func TestIntegrationNetOSTakesOverFromNetworkd(t *testing.T) {
	requireIntegration(t)
	if _, err := exec.LookPath("networkctl"); err != nil {
		t.Skip("нет networkctl")
	}
	if !unitActive("systemd-networkd.service") {
		t.Skip("systemd-networkd не запущен")
	}

	const iface = "nctest-take"
	const address = "10.99.66.1/24"

	_ = exec.Command("ip", "link", "del", iface).Run()
	if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("не удалось создать %s: %v\n%s", iface, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })

	// Сначала интерфейсом управляет networkd и выдаёт адрес сам.
	managed := filepath.Join(networkdDir, networkdPrefix+iface+".network")
	body := "[Match]\nName=" + iface + "\n\n[Network]\nAddress=10.99.66.9/24\n"
	if err := os.WriteFile(managed, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(managed)
		_ = exec.Command("networkctl", "reload").Run()
	})
	if out, err := exec.Command("networkctl", "reload").CombinedOutput(); err != nil {
		t.Fatalf("networkctl reload: %v\n%s", err, out)
	}
	if !waitFor(t, 15*time.Second, func() bool { return hasAddress(iface, "10.99.66.9/24") }) {
		t.Fatal("networkd не назначил свой адрес — проверять нечего")
	}

	// Теперь адрес назначает netOS — ровно той командой, что и подсистема wan.
	if out, err := exec.Command("ip", "addr", "replace", address, "dev", iface).CombinedOutput(); err != nil {
		t.Fatalf("не удалось назначить адрес netOS: %v\n%s", err, out)
	}

	// И netOS забирает адресацию себе тем же кодом, что и в бою.
	cfg := config.Default()
	cfg.System.NetworkBackend = "netos"
	cfg.Interfaces = []config.Interface{{ID: "if-x", Name: iface, Type: "physical", Enabled: true}}
	s := New(system.NewExec(), nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("передача управления не удалась: %v", err)
	}
	time.Sleep(3 * time.Second)

	t.Run("адрес netOS пережил передачу", func(t *testing.T) {
		if !hasAddress(iface, address) {
			t.Fatalf("адрес снят при передаче, интерфейс остался с %v", addressesOf(iface))
		}
	})

	t.Run("линк остался видимым для networkd", func(t *testing.T) {
		out, _ := exec.Command("networkctl", "status", iface).Output()
		if strings.Contains(string(out), "unmanaged") {
			t.Fatalf("линк скрыт от networkd — загрузка будет ждать таймаут:\n%s", out)
		}
	})

	t.Run("ожидание сети не упирается в таймаут", func(t *testing.T) {
		start := time.Now()
		cmd := exec.Command("/usr/lib/systemd/systemd-networkd-wait-online", "--timeout=20")
		err := cmd.Run()
		elapsed := time.Since(start)
		if err != nil || elapsed > 10*time.Second {
			t.Fatalf("ожидание сети заняло %s (ошибка: %v) — загрузка будет тормозить", elapsed.Round(time.Second), err)
		}
	})
}

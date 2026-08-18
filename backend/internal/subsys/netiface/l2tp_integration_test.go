//go:build linux

package netiface

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// Проверка клиента L2TP против настоящего концентратора.
//
// Стенд — тот же, что у PPPoE: пара veth, концентратор в отдельном network
// namespace. Роль LNS играет тот же xl2tpd, только с секцией [lns default].
//
// NETOS_INTEGRATION=1 go test ./internal/subsys/netiface/ -run L2TP -v
const (
	l2tpNetns      = "netos-l2tptest"
	l2tpServerIf   = "l2tptest-srv"
	l2tpClientIf   = "l2tptest-cli"
	l2tpServerAddr = "10.98.77.1"
	l2tpClientAddr = "10.98.77.2"
	// Адреса, которые LNS выдаёт внутри туннеля.
	l2tpPeerAddr  = "10.98.88.1"
	l2tpLocalAddr = "10.98.88.2"
	l2tpUser      = "netos-l2tp-user"
	l2tpPassword  = "netos-l2tp-password"
)

func TestL2TPDialsUpAgainstRealConcentrator(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("интеграционный тест: NETOS_INTEGRATION=1 и root")
	}
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
	for _, bin := range []string{"xl2tpd", "pppd", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s", bin)
		}
	}

	setupL2TPLink(t)
	setupL2TPSecrets(t)
	startLNS(t)

	w := config.WAN{
		ID: "l2tp1", Name: "Тестовый провайдер", Interface: "if-wan", Enabled: true,
		Proto: "l2tp", Server: l2tpServerAddr,
		Username: l2tpUser, Password: l2tpPassword,
		// Метрика заведомо хуже боевых маршрутов машины: тестовый туннель не
		// должен перехватить трафик и оборвать управление стендом. И отличается
		// от метрики стенда PPPoE: два маршрута по умолчанию с одной метрикой
		// мешали бы друг другу, если стенды запущены подряд.
		Metric: 4100,
	}

	// Файлы те же самые, что уйдут в бой.
	dir := t.TempDir()
	confPath := dir + "/xl2tpd.conf"
	pppPath := l2tpPPPPath(w.ID)
	conf := strings.Replace(renderL2TPConf(w), "pppoptfile = "+pppPath, "pppoptfile = "+pppPath, 1)
	if err := os.WriteFile(pppPath, []byte(renderL2TPPPP(w)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(pppPath) })
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	client := startXl2tpd(t, confPath, "netos-l2tp-client", pppPath)

	iface := L2TPInterface(w.ID)
	if !waitForL2TP(t, iface, 45*time.Second) {
		t.Fatalf("туннель не поднялся\nжурнал клиента:\n%s\nжурнал pppd:\n%s",
			client.String(), pppdJournal())
	}

	t.Run("интерфейс назван так, как ожидают правила файрволла", func(t *testing.T) {
		if iface != "ppp-l2tp1" {
			t.Fatalf("имя интерфейса %q", iface)
		}
		out, _ := exec.Command("ip", "-4", "addr", "show", "dev", iface).Output()
		if !strings.Contains(string(out), l2tpLocalAddr) {
			t.Fatalf("концентратор выдал не тот адрес:\n%s", out)
		}
	})

	t.Run("маршрут по умолчанию получил заданную метрику", func(t *testing.T) {
		out, _ := exec.Command("ip", "-4", "route", "show", "default", "dev", iface).Output()
		if !strings.Contains(string(out), "metric 4100") {
			t.Fatalf("метрика туннеля не применилась:\n%s", out)
		}
	})

	t.Run("MTU учитывает накладные расходы туннеля", func(t *testing.T) {
		// Читаем из sysfs: краткий вывод ip link значение MTU не печатает.
		raw, err := os.ReadFile("/sys/class/net/" + iface + "/mtu")
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(raw)); got != "1400" {
			t.Fatalf("MTU туннеля %s, ожидалось 1400: пакеты будут фрагментироваться", got)
		}
	})
}

// ---------------------------------------------------------------------------

func setupL2TPLink(t *testing.T) {
	t.Helper()
	teardownL2TPLink()
	mustRun(t, "ip", "netns", "add", l2tpNetns)
	t.Cleanup(teardownL2TPLink)

	mustRun(t, "ip", "link", "add", l2tpClientIf, "type", "veth", "peer", "name", l2tpServerIf)
	mustRun(t, "ip", "link", "set", l2tpServerIf, "netns", l2tpNetns)
	mustRun(t, "ip", "addr", "add", l2tpClientAddr+"/24", "dev", l2tpClientIf)
	mustRun(t, "ip", "link", "set", l2tpClientIf, "up")
	mustRun(t, "ip", "netns", "exec", l2tpNetns, "ip", "link", "set", "lo", "up")
	mustRun(t, "ip", "netns", "exec", l2tpNetns, "ip", "addr", "add", l2tpServerAddr+"/24", "dev", l2tpServerIf)
	mustRun(t, "ip", "netns", "exec", l2tpNetns, "ip", "link", "set", l2tpServerIf, "up")
}

func teardownL2TPLink() {
	if out, err := exec.Command("ip", "netns", "pids", l2tpNetns).Output(); err == nil {
		for _, pid := range strings.Fields(string(out)) {
			_ = exec.Command("kill", pid).Run()
		}
	}
	_ = exec.Command("ip", "netns", "del", l2tpNetns).Run()
	_ = exec.Command("ip", "link", "del", l2tpClientIf).Run()
}

// setupL2TPSecrets кладёт учётные данные для стороны концентратора. Сам netOS
// в общесистемные файлы ppp не пишет — его пароль лежит в собственных
// параметрах pppd.
func setupL2TPSecrets(t *testing.T) {
	t.Helper()
	for _, path := range []string{"/etc/ppp/pap-secrets", "/etc/ppp/chap-secrets"} {
		previous, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		line := l2tpUser + " * " + l2tpPassword + " *\n"
		if err := os.WriteFile(path, append(append([]byte{}, previous...), []byte(line)...), 0o600); err != nil {
			t.Fatal(err)
		}
		saved, savedPath := previous, path
		t.Cleanup(func() {
			if saved == nil {
				_ = os.Remove(savedPath)
				return
			}
			_ = os.WriteFile(savedPath, saved, 0o600)
		})
	}
}

// startLNS поднимает концентратор в отдельном namespace.
func startLNS(t *testing.T) {
	t.Helper()
	dir := t.TempDir()

	options := dir + "/lns.ppp"
	// Концентратор требует аутентификации — иначе тест не проверял бы, что
	// клиент вообще умеет представляться логином и паролем.
	body := "require-pap\nnoipv6\nlcp-echo-interval 10\nlcp-echo-failure 5\nms-dns " + l2tpServerAddr + "\n"
	if err := os.WriteFile(options, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	conf := dir + "/lns.conf"
	lns := "[global]\nport = 1701\n\n" +
		"[lns default]\n" +
		"ip range = " + l2tpLocalAddr + "-" + l2tpLocalAddr + "\n" +
		"local ip = " + l2tpPeerAddr + "\n" +
		"require authentication = yes\n" +
		"refuse chap = yes\n" +
		"pppoptfile = " + options + "\n" +
		"length bit = yes\n"
	if err := os.WriteFile(conf, []byte(lns), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("ip", "netns", "exec", l2tpNetns, "xl2tpd",
		"-D", "-c", conf, "-p", "/run/l2tptest-lns.pid", "-C", "/run/l2tptest-lns.ctl")
	sink := &strings.Builder{}
	cmd.Stdout, cmd.Stderr = sink, sink
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
		_ = exec.Command("pkill", "-f", options).Run()
		if t.Failed() {
			t.Logf("журнал концентратора:\n%s", sink.String())
		}
	})
	time.Sleep(time.Second)
}

func startXl2tpd(t *testing.T, conf, name, pppOptions string) *logBuffer {
	t.Helper()
	sink := &strings.Builder{}
	cmd := exec.Command("xl2tpd", "-D", "-c", conf,
		"-p", "/run/"+name+".pid", "-C", "/run/"+name+".ctl")
	cmd.Stdout, cmd.Stderr = sink, sink
	// Своя группа процессов: pppd запускает xl2tpd, и убийство одного лишь
	// родителя оставило бы сессию жить вместе с её интерфейсом и маршрутом
	// по умолчанию — стенд обязан за собой убирать.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
		// pppd мог успеть отвязаться от группы: добиваем по файлу параметров,
		// который принадлежит только этому стенду.
		_ = exec.Command("pkill", "-f", pppOptions).Run()
	})
	return &logBuffer{cmd: cmd, sink: sink}
}

func waitForL2TP(t *testing.T, iface string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ip", "-4", "-br", "addr", "show", "dev", iface).Output()
		if err == nil && strings.Contains(string(out), l2tpLocalAddr) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func pppdJournal() string {
	out, err := exec.Command("journalctl", "-t", "pppd", "--since", "-2 min", "--no-pager").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 40 {
		lines = lines[len(lines)-40:]
	}
	return strings.Join(lines, "\n")
}

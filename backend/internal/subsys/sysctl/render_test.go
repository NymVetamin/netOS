package sysctl

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Файл в /etc/sysctl.d читают глазами, и первый вопрос к любой строке —
// «откуда здесь это значение». Отвечать на него в документации, лежащей в
// другом месте, поздно.
func TestGeneratedFileExplainsItself(t *testing.T) {
	out := renderGroups(coreGroups(config.Default()))

	if !strings.HasPrefix(out, "# Сгенерировано netOS.") {
		t.Fatalf("файл не помечен как сгенерированный: %q", firstLine(out))
	}
	for _, want := range []string{
		"# ===== Маршрутизация =====",
		"# ===== Управление перегрузкой =====",
		"net.ipv4.ip_forward = 1",
		"net.ipv4.tcp_congestion_control = bbr",
		"netos render sysctl",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("в файле нет %q:\n%s", want, out)
		}
	}
}

// Значения применяются из того же списка, из которого печатается файл: иначе
// в /etc/sysctl.d будет написано одно, а в ядре стоять другое.
func TestAppliedValuesMatchGeneratedFile(t *testing.T) {
	cfg := config.Default()
	values := NewCore(nil).values(cfg)
	out := renderGroups(coreGroups(cfg))

	if len(values) == 0 {
		t.Fatal("список параметров пуст")
	}
	for key, value := range values {
		if !strings.Contains(out, key+" = "+value) {
			t.Fatalf("параметр %s=%s применяется, но в файл не попал", key, value)
		}
	}
}

// netos render sysctl отвечает на вопрос «что netOS сделал с ядром» целиком,
// а не по одному файлу: параметры разложены по двум, и искать второй
// администратор не обязан.
func TestRenderShowsEveryFileNetOSOwns(t *testing.T) {
	out := Render(config.Default())

	for _, want := range []string{confPath, ipv6ConfPath, modulesPath, "nf_conntrack"} {
		if !strings.Contains(out, want) {
			t.Fatalf("в выводе нет %q:\n%s", want, out)
		}
	}
}

// Диапазон локальных портов — тот же, из которого netfilter берёт порт при
// маскараде. Заход на 1024 столкнул бы NAT с портом панели.
func TestLocalPortRangeStartsAboveWellKnownServices(t *testing.T) {
	values := NewCore(nil).values(config.Default())
	got := values["net.ipv4.ip_local_port_range"]
	if !strings.HasPrefix(got, "10240 ") {
		t.Fatalf("диапазон портов %q заходит на порты служб", got)
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

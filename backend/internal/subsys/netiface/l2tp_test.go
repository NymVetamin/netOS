package netiface

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func l2tpWAN() config.WAN {
	return config.WAN{
		ID: "wan1", Name: "Провайдер", Interface: "if-wan", Enabled: true,
		Proto: "l2tp", Server: "tp.example.net",
		Username: "user", Password: "s3cret", Metric: 100,
	}
}

func TestL2TPConfDialsTheConcentrator(t *testing.T) {
	out := renderL2TPConf(l2tpWAN())
	for _, want := range []string{
		"[lac wan1]",
		"lns = tp.example.net",
		"name = user",
		// Дозвон при старте и бесконечный перезвон: обрыв у провайдера не
		// должен требовать вмешательства человека.
		"autodial = yes",
		"redial = yes",
		"max redials = 2000000000",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет строки %q:\n%s", want, out)
		}
	}
	// Роутер здесь клиент; принимать чужие туннели он не должен.
	if !strings.Contains(out, "access control = no") {
		t.Fatalf("не задан контроль доступа:\n%s", out)
	}
}

func TestL2TPAcceptsEitherAuthScheme(t *testing.T) {
	out := renderL2TPConf(l2tpWAN())
	// Провайдеры используют и PAP, и CHAP. Навязать один — значит не
	// подключиться к части концентраторов.
	for _, want := range []string{"require pap = no", "require chap = no", "refuse pap = no", "refuse chap = no"} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет строки %q:\n%s", want, out)
		}
	}
}

func TestL2TPPPPUsesTunnelMTUAndOwnInterfaceName(t *testing.T) {
	out := renderL2TPPPP(l2tpWAN())
	// Имя интерфейса задаём сами: на него ссылаются зоны файрволла.
	if !strings.Contains(out, "ifname ppp-wan1") {
		t.Fatalf("имя интерфейса не задано:\n%s", out)
	}
	// Туннель добавляет заголовки поверх IP — 1500 здесь не пройдёт.
	if !strings.Contains(out, "mtu 1400") || !strings.Contains(out, "mru 1400") {
		t.Fatalf("MTU не учитывает накладные расходы туннеля:\n%s", out)
	}
	if !strings.Contains(out, "defaultroute-metric 100") {
		t.Fatalf("метрика аплинка не передана:\n%s", out)
	}
	if !strings.Contains(out, "noipv6") {
		t.Fatalf("IPv6 не подавлен:\n%s", out)
	}
}

// Перезвоном занимается xl2tpd. persist в параметрах pppd означал бы два
// механизма, тянущих соединение в разные стороны.
func TestL2TPLeavesRedialToXl2tpd(t *testing.T) {
	out := renderL2TPPPP(l2tpWAN())
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "persist" {
			t.Fatalf("pppd перезванивает сам, хотя это делает xl2tpd:\n%s", out)
		}
	}
}

// Маршрут по умолчанию через сеть провайдера обязан быть хуже туннельного:
// иначе интернет пойдёт мимо туннеля, как только тот поднимется.
func TestL2TPUnderlayLosesToTheTunnel(t *testing.T) {
	w := l2tpWAN()
	if underlayMetric(w) <= w.Metric {
		t.Fatalf("метрика подложки %d не хуже туннельной %d", underlayMetric(w), w.Metric)
	}
	if underlayWAN(w).Metric != underlayMetric(w) {
		t.Fatal("подложка получила не ту метрику")
	}
	// Сам туннель метрику не меняет.
	if w.Metric != 100 {
		t.Fatal("изменён исходный аплинк")
	}
}

func TestL2TPUnitRunsXl2tpdInForeground(t *testing.T) {
	unit := l2tpUnit(l2tpWAN())
	// -D держит демон на переднем плане, чтобы за перезапуском следил systemd.
	if !strings.Contains(unit, "/usr/sbin/xl2tpd -D -c /var/lib/netos/generated/l2tp-wan1.conf") {
		t.Fatalf("юнит запускает не то:\n%s", unit)
	}
}

func TestL2TPStaticUnderlayIsValidated(t *testing.T) {
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "l2tp", Installed: true}}
	cfg.Interfaces = []config.Interface{{ID: "if-wan", Name: "eth0", Type: "physical"}}
	w := l2tpWAN()
	w.Underlay = "static" // адрес и шлюз не заданы
	cfg.WANs = []config.WAN{w}

	var address, gateway bool
	for _, p := range cfg.Validate().Problems {
		if strings.Contains(p.Path, "address") {
			address = true
		}
		if strings.Contains(p.Path, "gateway") {
			gateway = true
		}
	}
	if !address || !gateway {
		t.Fatal("статическая подложка без адреса и шлюза принята: туннелю не от чего оттолкнуться")
	}

	// С заполненными полями претензий быть не должно.
	w.Address, w.Gateway = "10.0.0.5/24", "10.0.0.1"
	cfg.WANs = []config.WAN{w}
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" && strings.HasPrefix(p.Path, "wans[0]") {
			t.Fatalf("корректная подложка отклонена: %s — %s", p.Path, p.Message)
		}
	}
}

// По умолчанию адрес под туннелем приходит по DHCP: так работает большинство
// провайдеров, и требовать явного выбора незачем.
func TestL2TPUnderlayDefaultsToDHCP(t *testing.T) {
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "l2tp", Installed: true}}
	cfg.Interfaces = []config.Interface{{ID: "if-wan", Name: "eth0", Type: "physical"}}
	cfg.WANs = []config.WAN{l2tpWAN()} // Underlay пуст

	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" && strings.HasPrefix(p.Path, "wans[0]") {
			t.Fatalf("пустой способ получения адреса отклонён: %s — %s", p.Path, p.Message)
		}
	}
}

// pppd 2.5 не знает опции lock, а nodetach и pppol2tp xl2tpd передаёт сам.
// Лишняя строка здесь означает не «безобидную избыточность», а неработающий
// аплинк: pppd отказывается запускаться с неизвестной опцией.
func TestL2TPPPPHasNoOptionsPppdWillReject(t *testing.T) {
	out := renderL2TPPPP(l2tpWAN())
	for _, line := range strings.Split(out, "\n") {
		switch strings.TrimSpace(line) {
		case "lock", "nodetach", "plugin pppol2tp.so":
			t.Fatalf("в параметрах есть %q — pppd не запустится или получит её дважды:\n%s", line, out)
		}
	}
}

// Метрика решает, какой аплинк основной. Две одинаковые означают, что выбор
// остаётся за ядром, а переключение при отказе становится непредсказуемым.
func TestUplinkMetricsMustBeUnique(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "if-a", Name: "eth0", Type: "physical"},
		{ID: "if-b", Name: "eth1", Type: "physical"},
	}
	cfg.WANs = []config.WAN{
		{ID: "a", Name: "Первый", Interface: "if-a", Enabled: true, Proto: "dhcp", Metric: 100},
		{ID: "b", Name: "Второй", Interface: "if-b", Enabled: true, Proto: "dhcp", Metric: 100},
	}
	if !hasProblem(cfg, "metric", "уникальным") {
		t.Fatal("два аплинка с одинаковым приоритетом приняты")
	}

	cfg.WANs[1].Metric = 200
	if hasProblem(cfg, "metric", "уникальным") {
		t.Fatal("разные приоритеты отклонены")
	}

	// Выключенный аплинк ни за что не борется и метрику не занимает.
	cfg.WANs[1].Enabled = false
	cfg.WANs[1].Metric = 100
	if hasProblem(cfg, "metric", "уникальным") {
		t.Fatal("выключенный аплинк занял приоритет")
	}
}

// Сеть провайдера под туннелем получает собственный маршрут по умолчанию,
// и он тоже участвует в общем порядке аплинков.
func TestL2TPUnderlayMetricParticipatesInOrdering(t *testing.T) {
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "l2tp", Installed: true}}
	cfg.Interfaces = []config.Interface{
		{ID: "if-a", Name: "eth0", Type: "physical"},
		{ID: "if-b", Name: "eth1", Type: "physical"},
	}
	tunnel := l2tpWAN()
	tunnel.ID, tunnel.Interface, tunnel.Metric = "t", "if-a", 100
	cfg.WANs = []config.WAN{
		tunnel,
		// 110 — это метрика сети провайдера под туннелем.
		{ID: "b", Name: "Второй", Interface: "if-b", Enabled: true, Proto: "dhcp", Metric: 110},
	}
	if !hasProblem(cfg, "metric", "уникальным") {
		t.Fatal("приоритет сети провайдера под туннелем не учтён")
	}
}

func hasProblem(cfg *config.Config, pathPart, messagePart string) bool {
	for _, p := range cfg.Validate().Problems {
		if strings.Contains(p.Path, pathPart) && strings.Contains(p.Message, messagePart) {
			return true
		}
	}
	return false
}

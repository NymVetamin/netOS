package netiface

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func pppoeWAN() config.WAN {
	return config.WAN{
		ID: "wan1", Name: "Провайдер", Interface: "if-wan", Enabled: true,
		Proto: "pppoe", Username: "user@isp", Password: "s3cret", Metric: 100,
	}
}

func TestPPPoEConfCarriesCredentialsAndInterface(t *testing.T) {
	out := renderPPPoEConf(pppoeWAN(), "eth0")
	for _, want := range []string{
		"plugin rp-pppoe.so",
		"nic-eth0",
		// Имя интерфейса задаём сами: на него ссылаются зоны файрволла, а
		// автоматический ppp0 зависел бы от порядка подключения аплинков.
		"ifname ppp-wan1",
		`user "user@isp"`,
		`password "s3cret"`,
		"defaultroute-metric 100",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет строки %q:\n%s", want, out)
		}
	}
}

func TestPPPoEConfSuppressesIPv6AndKeepsResolvConf(t *testing.T) {
	out := renderPPPoEConf(pppoeWAN(), "eth0")
	if !strings.Contains(out, "noipv6") {
		t.Fatalf("IPv6 не подавлен:\n%s", out)
	}
	// usepeerdns заставил бы pppd писать серверы имён провайдера мимо
	// конфигурации резолвера, которой владеет netOS.
	if strings.Contains(out, "\nusepeerdns") {
		t.Fatalf("pppd будет управлять DNS:\n%s", out)
	}
}

func TestPPPoEConfReconnectsWithoutHumanHelp(t *testing.T) {
	out := renderPPPoEConf(pppoeWAN(), "eth0")
	// Ночной обрыв у провайдера не должен требовать вмешательства.
	for _, want := range []string{"persist", "maxfail 0", "lcp-echo-interval 20", "lcp-echo-failure 3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет строки %q:\n%s", want, out)
		}
	}
}

func TestPPPoEMTUDefaultsToPPPoEOverhead(t *testing.T) {
	out := renderPPPoEConf(pppoeWAN(), "eth0")
	// 1500 минус 8 байт заголовка PPPoE.
	if !strings.Contains(out, "mtu 1492") || !strings.Contains(out, "mru 1492") {
		t.Fatalf("MTU по умолчанию не учитывает накладные расходы PPPoE:\n%s", out)
	}

	w := pppoeWAN()
	w.MTU = 1400
	out = renderPPPoEConf(w, "eth0")
	if !strings.Contains(out, "mtu 1400") {
		t.Fatalf("заданный MTU проигнорирован:\n%s", out)
	}
}

func TestPPPoEOptionalFieldsAreOmittedWhenEmpty(t *testing.T) {
	out := renderPPPoEConf(pppoeWAN(), "eth0")
	// Пустое имя услуги — обычный случай; передавать его пустым нельзя,
	// концентратор откажет в подключении.
	if strings.Contains(out, "rp_pppoe_service") || strings.Contains(out, "rp_pppoe_ac") {
		t.Fatalf("пустые необязательные параметры попали в конфигурацию:\n%s", out)
	}

	w := pppoeWAN()
	w.Service, w.AC = "internet", "bras1"
	out = renderPPPoEConf(w, "eth0")
	if !strings.Contains(out, `rp_pppoe_service "internet"`) ||
		!strings.Contains(out, `rp_pppoe_ac "bras1"`) {
		t.Fatalf("заданные параметры не переданы:\n%s", out)
	}
}

func TestPPPoEInterfaceNameFitsKernelLimit(t *testing.T) {
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "pppoe", Installed: true}}
	cfg.Interfaces = []config.Interface{{ID: "if-wan", Name: "eth0", Type: "physical"}}
	w := pppoeWAN()
	w.ID = "очень-длинный-идентификатор"
	cfg.WANs = []config.WAN{w}

	var found bool
	for _, p := range cfg.Validate().Problems {
		if strings.Contains(p.Message, "не помещается") {
			found = true
		}
	}
	if !found {
		t.Fatal("слишком длинное имя интерфейса не поймано до применения")
	}
}

func TestPPPoEUnitPointsAtGeneratedConf(t *testing.T) {
	unit := pppoeUnit(pppoeWAN(), "eth0", "/var/lib/netos/generated/pppoe-wan1.conf")
	if !strings.Contains(unit, "ExecStart=/usr/sbin/pppd file /var/lib/netos/generated/pppoe-wan1.conf nodetach") {
		t.Fatalf("юнит запускает не то:\n%s", unit)
	}
	// Без привязки к устройству юнит будет падать в цикле, пока интерфейс
	// не появится.
	if !strings.Contains(unit, "BindsTo=sys-subsystem-net-devices-eth0.device") {
		t.Fatalf("юнит не привязан к интерфейсу:\n%s", unit)
	}
}

package netiface

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Точку доступа в мост включает сам hostapd, и в составе моста её нет. Пока эти
// устройства не попадали в список сохраняемых, любое применение конфигурации
// выводило работающую точку из моста: клиенты оставались подключёнными к SSID,
// но теряли шлюз и весь сегмент.
func TestWiFiDevicesCountAsBridgeMembers(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan-if", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan-if", RouterAddress: "192.168.50.1/24", Enabled: true}}
	cfg.WiFi = []config.WiFiRadio{{
		ID: "r0", Device: "wlan0", Enabled: true,
		SSIDs: []config.WiFiSSID{
			{ID: "s1", SSID: "netos", Enabled: true, Network: "lan"},
			{ID: "s2", SSID: "guest", Enabled: true, Network: "lan"},
		},
	}}
	got := wifiDevicesOn(cfg, "lan-if")
	if strings.Join(got, ",") != "wlan0,wlan0-n1" {
		t.Fatalf("устройства точки доступа не признаны портами моста: %v", got)
	}
	if other := wifiDevicesOn(cfg, "нет-такого"); len(other) != 0 {
		t.Fatalf("чужой сегмент получил устройства Wi-Fi: %v", other)
	}
}

// Заданный аплинку MTU относится к сессии PPPoE, а не к кадру под ней: плагин
// rp-pppoe вычитает из физического MTU восемь байт заголовка. Пока то же число
// ставилось физическому интерфейсу, полезный MTU выходил ещё на восемь меньше
// заказанного.
func TestPPPoEUnderlayKeepsRoomForHeader(t *testing.T) {
	pppoe := config.WAN{Proto: "pppoe", MTU: 1492}
	if got := underlayMTU(pppoe, 1400); got != 1500 {
		t.Fatalf("подложка PPPoE получила MTU %d вместо 1500", got)
	}
	if got := underlayMTU(pppoe, 9000); got != 0 {
		t.Fatalf("уже достаточный MTU 9000 занижен до %d", got)
	}
	if got := underlayMTU(config.WAN{Proto: "dhcp", MTU: 1400}, 1500); got != 1400 {
		t.Fatalf("обычный аплинк получил MTU %d вместо заданных 1400", got)
	}
	if got := underlayMTU(config.WAN{Proto: "pppoe"}, 1500); got != 0 {
		t.Fatalf("незаданный MTU превратился в %d", got)
	}
}

// Обработчик событий udhcpc вызывается и при остановке юнита. Пока обе ветки
// были одной, остановка клиента поднимала порт, только что выключенный в
// панели, и проверка после применения откатывала весь Apply.
func TestDHCPScriptRaisesLinkOnlyWhenStartingClient(t *testing.T) {
	script := renderDHCPScript(100)
	deconfig, release, ok := strings.Cut(script, "    release)")
	if !ok {
		t.Fatal("в обработчике нет отдельной ветки release")
	}
	if !strings.Contains(deconfig, `ip link set "$interface" up`) {
		t.Fatal("старт клиента больше не поднимает линк — DISCOVER уйти не сможет")
	}
	release, _, _ = strings.Cut(release, "    bound|renew)")
	if strings.Contains(release, `ip link set "$interface" up`) {
		t.Fatal("остановка клиента поднимает линк, которым владеет подсистема интерфейсов")
	}
	if !strings.Contains(release, "route flush default") {
		t.Fatal("остановка клиента не убирает за собой маршрут")
	}
	if !strings.Contains(dhcpUnit("eth0", "/tmp/s.sh"), "/tmp/s.sh release") {
		t.Fatal("юнит по-прежнему вызывает при остановке ветку старта")
	}
}

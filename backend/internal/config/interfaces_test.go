package config

import (
	"strings"
	"testing"
)

func problem(t *testing.T, cfg *Config, pathPart, textPart string) bool {
	t.Helper()
	for _, p := range cfg.Validate().Problems {
		if strings.Contains(p.Path, pathPart) && strings.Contains(p.Message, textPart) {
			return true
		}
	}
	return false
}

func lanConfig() *Config {
	cfg := Default()
	cfg.Interfaces = []Interface{
		{ID: "if-1", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "if-2", Name: "eth1", Type: "physical", Enabled: true},
		{ID: "if-br", Name: "lan", Type: "bridge", Members: []string{"if-1", "if-2"}, Enabled: true},
	}
	cfg.Networks = []Network{{
		ID: "n1", Name: "LAN", Interface: "if-br",
		RouterAddress: "192.168.10.1/24", Zone: "lan", Enabled: true,
	}}
	return cfg
}

// Связи описаны идентификаторами, но конфигурация с прежней версии схемы
// хранит там имена. Без перевода мост остался бы без портов, а VLAN без
// родителя — и притом молча.
func TestNormalizeTranslatesNamesToIDs(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{
		{ID: "if-1", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "if-br", Name: "br-lan", Type: "bridge", Members: []string{"eth0"}, Enabled: true},
		{ID: "if-v", Name: "vl-10", Type: "vlan", Parent: "br-lan", VLANID: 10, Enabled: true},
	}
	cfg.Normalize()

	if got := cfg.Interfaces[1].Members[0]; got != "if-1" {
		t.Fatalf("состав моста не переведён в идентификаторы: %q", got)
	}
	if got := cfg.Interfaces[2].Parent; got != "if-br" {
		t.Fatalf("родитель VLAN не переведён в идентификатор: %q", got)
	}
	// Повторный вызов ничего не должен испортить: идентификатор уже на месте.
	cfg.Normalize()
	if got := cfg.Interfaces[2].Parent; got != "if-br" {
		t.Fatalf("повторная нормализация испортила ссылку: %q", got)
	}
}

// Переименование интерфейса не должно рвать связи: именно ради этого они
// хранятся идентификаторами.
func TestRenameKeepsLinks(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces[0].Name = "enp3s0"
	cfg.Normalize()

	if got := cfg.InterfaceNames(cfg.Interfaces[2].Members); got[0] != "enp3s0" {
		t.Fatalf("состав моста после переименования: %v", got)
	}
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" && strings.HasPrefix(p.Path, "interfaces") {
			t.Fatalf("переименование сломало конфигурацию: %s — %s", p.Path, p.Message)
		}
	}
}

// Порт входит ровно в один мост. Двух хозяев ядро не даёт: применится тот, кто
// окажется последним, — и не тот, кого выбрали.
func TestPortCannotBelongToTwoBridges(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces = append(cfg.Interfaces, Interface{
		ID: "if-br2", Name: "guest", Type: "bridge", Members: []string{"if-2"}, Enabled: true,
	})
	if !problem(t, cfg, "members", "уже входит") {
		t.Fatal("порт в двух мостах принят")
	}
}

// У подчинённого порта нет своего адреса: весь трафик уходит мосту. Сегмент,
// назначенный на такой порт, не заработал бы, а панель показывала бы обратное.
func TestSegmentOnEnslavedPortIsRejected(t *testing.T) {
	cfg := lanConfig()
	cfg.Networks[0].Interface = "if-1"
	if !problem(t, cfg, "networks[0].interface", "назначьте сегмент самому мосту") {
		t.Fatal("сегмент на подчинённом порту принят")
	}
}

// Аплинк на подчинённом порту не поднимется по той же причине.
func TestUplinkOnEnslavedPortIsRejected(t *testing.T) {
	cfg := lanConfig()
	cfg.WANs = []WAN{{
		ID: "w1", Name: "Провайдер", Interface: "if-1",
		Enabled: true, Proto: "dhcp", Metric: 100,
	}}
	if !problem(t, cfg, "wans[0].interface", "аплинк на подчинённом порту") {
		t.Fatal("аплинк на подчинённом порту принят")
	}
}

// Аплинк и локальный сегмент на одной карте не уживаются: подсистема аплинков
// снимает с интерфейса все адреса, кроме своего.
func TestSegmentAndUplinkShareNoInterface(t *testing.T) {
	cfg := lanConfig()
	cfg.Networks[0].Interface = "if-br"
	cfg.WANs = []WAN{{
		ID: "w1", Name: "Провайдер", Interface: "if-br",
		Enabled: true, Proto: "dhcp", Metric: 100,
	}}
	if !problem(t, cfg, "wans[0].interface", "не уживаются") {
		t.Fatal("сегмент и аплинк на одном интерфейсе приняты")
	}
}

// VLAN над подчинённым портом останется пустым: тегированный трафик уйдёт в
// мост целиком.
func TestVLANOverEnslavedParentIsRejected(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces = append(cfg.Interfaces, Interface{
		ID: "if-v", Name: "eth1.10", Type: "vlan", Parent: "if-2", VLANID: 10, Enabled: true,
	})
	if !problem(t, cfg, "parent", "останется пустым") {
		t.Fatal("VLAN над подчинённым портом принят")
	}
}

// Мост в мост ядро не вкладывает.
func TestBridgeCannotBeMemberOfBridge(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces = append(cfg.Interfaces, Interface{
		ID: "if-br2", Name: "guest", Type: "bridge", Members: []string{"if-br"}, Enabled: true,
	})
	if !problem(t, cfg, "members", "нельзя включить") {
		t.Fatal("мост, вложенный в мост, принят")
	}
}

// Два VLAN с одним номером на одном родителе — это один интерфейс, второй ядро
// не создаст.
func TestDuplicateVLANIDOnSameParent(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces = append(cfg.Interfaces,
		Interface{ID: "if-v1", Name: "lan.10", Type: "vlan", Parent: "if-br", VLANID: 10, Enabled: true},
		Interface{ID: "if-v2", Name: "lan.10b", Type: "vlan", Parent: "if-br", VLANID: 10, Enabled: true},
	)
	if !problem(t, cfg, "vlan_id", "уже описан") {
		t.Fatal("два VLAN с одним номером на одном родителе приняты")
	}
}

// Ядро режет имя интерфейса на 15 символах молча, а на имя ссылаются зоны
// файрволла: правило ушло бы в пустоту.
func TestTooLongInterfaceNameIsRejected(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces[2].Name = "очень-длинное-имя-моста"
	if !problem(t, cfg, "interfaces[2].name", "ядро не примет") {
		t.Fatal("непригодное имя интерфейса принято")
	}
}

func TestBridgeCarrierNamesAreStableAndDistinct(t *testing.T) {
	dummy, peer := BridgeCarrierNames("br-lan")
	if dummy != "d-lan" || peer != "p-lan" {
		t.Fatalf("short legacy carrier names changed: %s/%s", dummy, peer)
	}
	d1, p1 := BridgeCarrierNames("abcdefghijklm01")
	d2, p2 := BridgeCarrierNames("abcdefghijklm02")
	if d1 == d2 || p1 == p2 || len(d1) > maxInterfaceName || len(p1) > maxInterfaceName {
		t.Fatalf("long bridge carrier collision or overflow: %s/%s and %s/%s", d1, p1, d2, p2)
	}
}

func TestEmptyBridgeCarrierCannotCollideWithDeclaredInterface(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{
		{ID: "bridge", Name: "lan", Type: "bridge", Enabled: true},
		{ID: "physical", Name: "d-lan", Type: "physical", Enabled: true},
	}
	if !problem(t, cfg, "interfaces[0].name", "carrier") {
		t.Fatalf("declared interface may steal hidden bridge carrier: %#v", cfg.Validate().Problems)
	}
}

func TestDistinctLongEmptyBridgesHaveDistinctCarriers(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{
		{ID: "bridge1", Name: "abcdefghijklm01", Type: "bridge", Enabled: true},
		{ID: "bridge2", Name: "abcdefghijklm02", Type: "bridge", Enabled: true},
	}
	for _, item := range cfg.Validate().Problems {
		if item.Severity == "error" && strings.HasPrefix(item.Path, "interfaces") {
			t.Fatalf("distinct valid bridges rejected: %#v", cfg.Validate().Problems)
		}
	}
}

// Ссылка на удалённый интерфейс — ошибка, а не молчаливый пропуск: иначе мост
// остался бы без порта, и никто бы об этом не сказал.
func TestDanglingMemberIsReported(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces[2].Members = []string{"if-1", "if-нет"}
	if !problem(t, cfg, "members", "не существует") {
		t.Fatal("ссылка на несуществующий порт принята молча")
	}
}

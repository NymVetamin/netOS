package config

import "testing"

// Проверка защиты от самоблокировки. Эти тесты существуют потому, что
// конфигурация без разрешающих правил однажды уже отрезала доступ к живой
// машине: роутер применил политику DROP и перестал отвечать совсем.

func TestDefaultConfigIsReachable(t *testing.T) {
	cfg := Default()
	if !cfg.reachableForManagement() {
		t.Fatal("конфигурация по умолчанию не оставляет доступа к роутеру")
	}
	res := cfg.Validate()
	if res.HasErrors() {
		for _, p := range res.Problems {
			if p.Severity == "error" {
				t.Errorf("неожиданная ошибка: %s: %s", p.Path, p.Message)
			}
		}
		t.Fatal("конфигурация по умолчанию не проходит проверку")
	}
}

func TestDefaultConfigHasSystemRules(t *testing.T) {
	cfg := Default()
	want := []string{RuleLoopback, RuleEstablishedIn, RuleSSH, RulePanel}
	for _, id := range want {
		found := false
		for _, r := range cfg.Firewall.Rules {
			if r.ID == id && r.Enabled {
				found = true
			}
		}
		if !found {
			t.Errorf("в конфигурации по умолчанию нет включённого правила %s", id)
		}
	}
}

func TestEmptyRulesWithDropPolicyIsRejected(t *testing.T) {
	cfg := Default()
	// Воспроизводим ровно тот случай, который положил машину: правил нет,
	// зоны запрещают входящие.
	cfg.Firewall.Rules = nil
	for i := range cfg.Firewall.Zones {
		cfg.Firewall.Zones[i].Policy = "drop"
	}

	if cfg.reachableForManagement() {
		t.Fatal("конфигурация без правил и с политикой drop признана доступной")
	}

	res := cfg.Validate()
	if !res.HasErrors() {
		t.Fatal("конфигурация, отрезающая доступ, прошла проверку")
	}
}

func TestDisablingAccessRulesIsRejected(t *testing.T) {
	cfg := Default()
	for i := range cfg.Firewall.Zones {
		cfg.Firewall.Zones[i].Policy = "drop"
	}
	// Выключаем всё, что пускает на роутер снаружи.
	for i := range cfg.Firewall.Rules {
		switch cfg.Firewall.Rules[i].ID {
		case RuleSSH, RulePanel, RuleICMP:
			cfg.Firewall.Rules[i].Enabled = false
		}
	}

	if cfg.reachableForManagement() {
		t.Fatal("доступ признан возможным, хотя все входящие правила выключены")
	}
}

// Правило про установленные соединения новых подключений не пропускает, а
// петля работает только локально — ни то, ни другое не считается доступом.
func TestEstablishedAndLoopbackDoNotCount(t *testing.T) {
	cfg := Default()
	for i := range cfg.Firewall.Zones {
		cfg.Firewall.Zones[i].Policy = "drop"
	}
	cfg.Firewall.Rules = []FirewallRule{
		{
			ID: RuleEstablishedIn, Enabled: true, Zone: "global", Flow: "any",
			Action: "accept", ConnState: "established,related",
		},
		{
			ID: RuleLoopback, Enabled: true, Zone: "global", Flow: "router",
			Action: "accept", Interface: "lo",
		},
	}
	if cfg.reachableForManagement() {
		t.Fatal("established и петля ошибочно засчитаны за доступ к роутеру")
	}
}

// Зона с политикой accept на живом интерфейсе — законный способ остаться
// доступным даже без явных правил.
func TestAcceptZonePolicyCounts(t *testing.T) {
	cfg := Default()
	cfg.Firewall.Rules = nil
	cfg.Interfaces = []Interface{{ID: "if1", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.WANs = []WAN{{ID: "wan", Interface: "if1", Enabled: true, Proto: "dhcp"}}
	for i := range cfg.Firewall.Zones {
		if cfg.Firewall.Zones[i].Name == "wan" {
			cfg.Firewall.Zones[i].Policy = "accept"
		} else {
			cfg.Firewall.Zones[i].Policy = "drop"
		}
	}
	if !cfg.reachableForManagement() {
		t.Fatal("зона wan с политикой accept не засчитана за доступ")
	}
}


// Шлюз вне подсети интерфейса ядро не примет: ip route отвечает «Nexthop has
// invalid gateway», применение падает и откатывается. Откат спасает связность,
// но аплинк к тому моменту уже перестроили. Предупреждаем заранее — и именно
// предупреждаем, потому что бывают точка-точка и шлюз за onlink-маршрутом.
func TestGatewayOutsideInterfaceSubnetIsWarningNotError(t *testing.T) {
	cfg := Default()
	cfg.WANs = []WAN{{
		ID: "wan", Name: "Аплинк", Interface: "if-wan", Enabled: true,
		Proto: "static", Address: "45.38.170.119/24", Gateway: "10.99.99.99", Metric: 100,
	}}
	cfg.Interfaces = []Interface{{ID: "if-wan", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.Normalize()

	res := cfg.Validate()
	var warned bool
	for _, p := range res.Problems {
		if p.Severity == "warning" && p.Path == "wans[0].gateway" {
			warned = true
		}
		if p.Severity == "error" && p.Path == "wans[0].gateway" {
			t.Fatalf("шлюз вне подсети объявлен ошибкой: %s", p.Message)
		}
	}
	if !warned {
		t.Fatalf("промах со шлюзом не замечен: %#v", res.Problems)
	}
}

// Обычный шлюз внутри подсети не должен вызывать ни слова.
func TestGatewayInsideSubnetIsSilent(t *testing.T) {
	cfg := Default()
	cfg.WANs = []WAN{{
		ID: "wan", Name: "Аплинк", Interface: "if-wan", Enabled: true,
		Proto: "static", Address: "45.38.170.119/24", Gateway: "45.38.170.1", Metric: 100,
	}}
	cfg.Interfaces = []Interface{{ID: "if-wan", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.Normalize()

	for _, p := range cfg.Validate().Problems {
		if p.Path == "wans[0].gateway" {
			t.Fatalf("исправный шлюз вызвал жалобу: %s", p.Message)
		}
	}
}

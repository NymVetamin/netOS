package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func ipv6PassthroughConfig() *config.Config {
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	cfg.Interfaces = []config.Interface{{ID: "uplink", Name: "eth0"}, {ID: "home", Name: "br-lan"}}
	cfg.WANs = []config.WAN{{ID: "isp", Name: "isp", Interface: "uplink", Enabled: true, Proto: "dhcp", Metric: 100}}
	cfg.Networks = []config.Network{{ID: "home", Name: "home", Interface: "home", Zone: "lan", Enabled: true, RouterAddress: "192.168.1.1/24"}}
	cfg.Normalize()
	return cfg
}

func ipv6FilterTable(t *testing.T, rules string) string {
	t.Helper()
	start := strings.Index(rules, "*filter\n")
	if start < 0 {
		t.Fatalf("нет таблицы filter:\n%s", rules)
	}
	return rules[start:]
}

// В режиме «Разрешить» IPv6 не должен обходить защиту сети: со стороны
// аплинка — только ответы, ICMPv6 и системные разрешения, как в IPv4.
func TestIPv6PassthroughFiltersUplink(t *testing.T) {
	cfg := ipv6PassthroughConfig()
	filter := ipv6FilterTable(t, buildIPv6(cfg))
	for _, want := range []string{
		":INPUT DROP [0:0]",
		":FORWARD DROP [0:0]",
		":OUTPUT ACCEPT [0:0]",
		"-A INPUT -i lo -j ACCEPT",
		"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A INPUT -p ipv6-icmp -j ACCEPT",
		"-A INPUT -i br-lan -j ACCEPT",
		"-A FORWARD -i br-lan -j ACCEPT",
		`-A INPUT -p tcp -m multiport --dports 22 -m comment --comment "Доступ по SSH" -j ACCEPT`,
		`-A INPUT -p tcp -m multiport --dports 80,8443 -m comment --comment "Веб-панель netOS" -j ACCEPT`,
	} {
		if !strings.Contains(filter, want+"\n") {
			t.Errorf("нет строки %q:\n%s", want, filter)
		}
	}
	if strings.Contains(filter, "-i eth0") {
		t.Fatalf("аплинк получил разрешение зоны с политикой drop:\n%s", filter)
	}

	// Выключенные администратором SSH и панель закрыты и по IPv6.
	for i := range cfg.Firewall.Rules {
		if id := cfg.Firewall.Rules[i].ID; id == config.RuleSSH || id == config.RulePanel {
			cfg.Firewall.Rules[i].Enabled = false
		}
	}
	filter = ipv6FilterTable(t, buildIPv6(cfg))
	if strings.Contains(filter, "--dports 22 ") || strings.Contains(filter, "8443") {
		t.Fatalf("выключенные правила остались в IPv6:\n%s", filter)
	}
}

// Правило с адресом IPv4 в ip6tables не применить, а без адреса оно открыло
// бы по IPv6 больше, чем по IPv4. Такое правило в IPv6 не переносится.
func TestIPv6PassthroughSkipsAddressRestrictedSystemRules(t *testing.T) {
	cfg := ipv6PassthroughConfig()
	for i := range cfg.Firewall.Rules {
		if cfg.Firewall.Rules[i].ID == config.RuleSSH {
			cfg.Firewall.Rules[i].SrcIP = "192.168.1.0/24"
		}
	}
	filter := ipv6FilterTable(t, buildIPv6(cfg))
	if strings.Contains(filter, "--dports 22 ") || strings.Contains(filter, "192.168.1.0/24") {
		t.Fatalf("правило с адресом IPv4 перенесено в IPv6:\n%s", filter)
	}
}

// Автоматические разрешения IPv4 повторяются в IPv6: иначе включение
// фильтрации сломало бы клиентов VPN с адресом IPv6 и проверку ACME по AAAA.
func TestIPv6PassthroughKeepsAutomaticAccepts(t *testing.T) {
	cfg := ipv6PassthroughConfig()
	cfg.VPNServers = []config.VPNServer{{ID: "wg", Name: "home", Type: "wireguard", Enabled: true, Index: 1, Port: 51820}}
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "router.example", Email: "admin@example.org"}
	cfg.Clients = []config.Client{{ID: "kid", Name: "tablet", MAC: "02:00:00:00:00:02", Blocked: true}}
	filter := ipv6FilterTable(t, buildIPv6(cfg))
	for _, want := range []string{
		`-A INPUT -p udp --dport 51820 -m comment --comment "VPN-сервер «home»" -j ACCEPT`,
		`-A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m comment --comment "ACME HTTP-01" -j ACCEPT`,
		`-A FORWARD -m mac --mac-source 02:00:00:00:00:02 -m comment --comment "заблокирован клиент tablet" -j DROP`,
	} {
		if !strings.Contains(filter, want+"\n") {
			t.Errorf("нет строки %q:\n%s", want, filter)
		}
	}
	// Блокировка клиента стоит раньше разрешения его сегмента.
	if strings.Index(filter, "--mac-source 02:00:00:00:00:02") > strings.Index(filter, "-A FORWARD -i br-lan -j ACCEPT") {
		t.Fatalf("разрешение сегмента раньше блокировки клиента:\n%s", filter)
	}
}

// Выключенная защита сети — честно открытый роутер, как и в IPv4.
func TestIPv6PassthroughWithFirewallDisabledStaysOpen(t *testing.T) {
	cfg := ipv6PassthroughConfig()
	cfg.Firewall.Enabled = false
	filter := ipv6FilterTable(t, buildIPv6(cfg))
	for _, policy := range []string{":INPUT ACCEPT", ":FORWARD ACCEPT", ":OUTPUT ACCEPT"} {
		if !strings.Contains(filter, policy) {
			t.Fatalf("нет %q:\n%s", policy, filter)
		}
	}
	if strings.Contains(filter, " DROP [") {
		t.Fatalf("выключенная защита оставила DROP:\n%s", filter)
	}
}

// Сгенерированный набор совпадает сам с собой после приведения к виду
// iptables-save — иначе проверка после применения откатывала бы конфигурацию.
func TestIPv6PassthroughRulesetMatchesItself(t *testing.T) {
	rules := buildIPv6(ipv6PassthroughConfig())
	if !rulesetMatches(rules, rules) {
		t.Fatal("набор не совпадает сам с собой")
	}
}

package render

import (
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/firewall"
)

func TestIPTablesPreviewTracksInterfaceState(t *testing.T) {
	for _, useVLAN := range []bool{false, true} {
		cfg := config.Default()
		port := config.Interface{ID: "port", Name: "eth7", Type: "physical", Enabled: true}
		cfg.Interfaces = []config.Interface{port}
		uplink := port
		if useVLAN {
			uplink = config.Interface{ID: "tag", Name: "eth7.12", Type: "vlan", VLANID: 12, Parent: port.ID, Enabled: true}
			cfg.Interfaces = append(cfg.Interfaces, uplink)
		}
		cfg.WANs = []config.WAN{{ID: "wan", Index: 1, Name: "uplink", Interface: uplink.ID, Proto: "dhcp", Enabled: true, Metric: 100, Weight: 1}}
		cfg.Normalize()
		for _, enabled := range []bool{true, false, true} {
			cfg.Interfaces[0].Enabled = enabled
			if v := cfg.Validate(); v.HasErrors() {
				t.Fatalf("invalid fixture: %v", v)
			}
			rules, err := firewall.Build(cfg.RuntimeNetworkConfig())
			if err != nil {
				t.Fatal(err)
			}
			got, err := Render("iptables", cfg)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(got, uplink.Name) != enabled || got != rules.IPv4+"\n# --- ip6tables ---\n"+rules.IPv6 {
				t.Fatalf("preview differs from effective rules (VLAN=%v, parent enabled=%v)", useVLAN, enabled)
			}
			if !cfg.WANs[0].Enabled || useVLAN && !cfg.Interfaces[1].Enabled {
				t.Fatal("preview modified the desired configuration")
			}
		}
	}
}

func BenchmarkIPTablesPreview(b *testing.B) {
	for _, n := range []int{32, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := config.Default()
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("eth%d", i)
				cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: name, Name: name, Type: "physical", Enabled: true})
			}
			cfg.WANs = []config.WAN{{ID: "wan", Interface: "eth0", Proto: "dhcp", Enabled: true}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Render("iptables", cfg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func ids(artifacts []Artifact) []string {
	out := make([]string, 0, len(artifacts))
	for _, a := range artifacts {
		out = append(out, a.ID)
	}
	return out
}

func has(list []string, id string) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// Диагностика обязана показывать конфигурацию демонов, которые работают. Когда
// список был зашит в панели, она показывала dnsmasq всегда — в том числе на
// машине с unbound и ISC DHCP, где dnsmasq выключен и его конфига на диске
// нет вовсе, а конфигов unbound и ISC не показывала.
func TestActiveFollowsChosenDaemons(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "isc-dhcp-server"
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "unbound", 53

	active := ids(Active(cfg))
	for _, want := range []string{"iptables", "isc-dhcp", "unbound", "resolv", "network", "sysctl"} {
		if !has(active, want) {
			t.Errorf("в диагностике нет %q: %v", want, active)
		}
	}
	for _, unwanted := range []string{"dnsmasq", "kea-dhcp4", "dnsproxy"} {
		if has(active, unwanted) {
			t.Errorf("показан выключенный %q: %v", unwanted, active)
		}
	}
}

// dnsmasq остаётся подчинённым резолвером локальной зоны, когда раздаёт адреса
// он, а порт 53 держит другой демон. Конфиг у него при этом свой и на машине
// есть — прятать его нельзя.
func TestActiveShowsDnsmasqInSubordinateRole(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "dnsmasq"
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "unbound", 53

	active := ids(Active(cfg))
	for _, want := range []string{"dnsmasq", "unbound"} {
		if !has(active, want) {
			t.Errorf("в диагностике нет %q: %v", want, active)
		}
	}
}

// Резолвер роутера на нестандартном порту netOS себе не забирает: показывать
// файл, которого он не пишет, — то же враньё, что и прятать работающий.
func TestActiveHidesResolvConfOnNonStandardPort(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "unbound", 5353

	if has(ids(Active(cfg)), "resolv") {
		t.Error("показан resolv.conf, которым netOS не владеет")
	}
}

// Каталог общий для панели и CLI: разойдясь, они снова начнут показывать
// разное. Заодно проверяем, что каждый артефакт вообще собирается.
func TestEveryArtifactRenders(t *testing.T) {
	cfg := config.Default()
	// Конфигурация сети пишется по интерфейсам: без единого интерфейса файл
	// пуст на законных основаниях, и проверять на нём нечего.
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{
		ID: "office", Interface: "lan", RouterAddress: "192.168.50.1/24", Enabled: true,
	}}
	for _, a := range All() {
		if a.Title == "" {
			t.Errorf("артефакт %q без названия для панели", a.ID)
		}
		out, err := a.Render(cfg)
		if err != nil {
			t.Errorf("артефакт %q не собрался: %v", a.ID, err)
			continue
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("артефакт %q собрался пустым", a.ID)
		}
	}
}

func TestTrafficMonitorArtifactFollowsConfiguration(t *testing.T) {
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{Type: "l2tp", Index: 2, Subnet: "10.9.0.0/24", Enabled: true}}
	for _, enabled := range []bool{false, true, false} {
		cfg.TrafficMonitor.Enabled = enabled
		if has(ids(Active(cfg)), "traffic-monitor") != enabled {
			t.Fatalf("unexpected visibility with enabled=%v", enabled)
		}
		rules, err := Render("traffic-monitor", cfg)
		if err != nil || strings.Contains(rules, `iifname "pp2-*" ip saddr { 10.9.0.0/24 }`) != enabled {
			t.Fatalf("unexpected accounting rules: %v\n%s", err, rules)
		}
	}
}

func TestXrayArtifactFollowsAndRendersChannel(t *testing.T) {
	cfg := config.Default()
	if has(ids(Active(cfg)), "xray") {
		t.Fatal("Xray artifact is active without an enabled channel")
	}
	cfg.Channels = append(cfg.Channels, config.Channel{
		ID: "xray-test", Index: 7, Name: "Xray test", Enabled: true,
		Type: "xray", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"mtu":      1400,
			"outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}},
		},
	})
	if !has(ids(Active(cfg)), "xray") {
		t.Fatal("enabled Xray channel is absent from diagnostics")
	}
	out, err := Render("xray", cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tun-ch7", "198.18.0.29/30", `"protocol": "freedom"`} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered Xray artifact lacks %q:\n%s", want, out)
		}
	}
}

func TestXrayServerArtifactFollowsServer(t *testing.T) {
	cfg := config.Default()
	if has(ids(Active(cfg)), "xray-servers") {
		t.Fatal("Xray server artifact is active without a server")
	}
	_, server := vpnserversTestConfig()
	cfg.VPNServers = []config.VPNServer{server}
	if !has(ids(Active(cfg)), "xray-servers") {
		t.Fatal("enabled Xray server is absent from diagnostics")
	}
	out, err := Render("xray-servers", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"protocol": "vless"`) || !strings.Contains(out, `"security": "reality"`) {
		t.Fatalf("unexpected Xray server artifact:\n%s", out)
	}
}

func vpnserversTestConfig() (*config.Config, config.VPNServer) {
	cfg := config.Default()
	server := config.VPNServer{
		ID: "reality", Index: 2, Name: "Reality", Enabled: true, Type: "xray", Port: 443,
		Subnet: "10.10.0.1/24", DefaultChannel: "direct",
		Config: map[string]any{
			"private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "destination": "www.example.com:443",
			"server_names": []string{"www.example.com"}, "short_ids": []string{"0123456789abcdef"},
		},
		Peers: []config.VPNPeer{{ID: "phone", Enabled: true, Address: "10.10.0.2", Credentials: map[string]string{"uuid": "123e4567-e89b-12d3-a456-426614174000"}}},
	}
	return cfg, server
}

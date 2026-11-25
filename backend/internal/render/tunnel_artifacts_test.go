package render

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Аплинки PPPoE/L2TP, клиенты-туннели и xl2tpd сервера пишут файлы в
// generated, но в каталоге `netos render` их не было.
func TestTunnelArtifactsFollowEnabledInstances(t *testing.T) {
	cfg := config.Default()
	for _, id := range []string{"ppp", "tunnel-clients", "l2tp-servers"} {
		if has(ids(Active(cfg)), id) {
			t.Errorf("artifact %q active without instances", id)
		}
		if out, err := Render(id, cfg); err != nil || !strings.HasPrefix(out, "# Нет активных") {
			t.Errorf("inactive %q: %q, %v", id, out, err)
		}
	}

	cfg.Interfaces = []config.Interface{{ID: "wan", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{
		{ID: "isp", Interface: "wan", Enabled: true, Proto: "pppoe", Username: "user", Password: "pass"},
		{ID: "off", Interface: "wan", Enabled: false, Proto: "l2tp", Username: "nobody"},
	}
	cfg.Channels = []config.Channel{
		{ID: "l2", Index: 2, Enabled: true, Type: "l2tp", Config: map[string]any{"server": "lns.example", "username": "chuser", "password": "chpass"}},
		{ID: "oc", Index: 3, Enabled: true, Type: "openconnect", Config: map[string]any{"server": "oc.example", "username": "ocuser", "password": "ocpass"}},
	}
	cfg.VPNServers = []config.VPNServer{{ID: "srv", Index: 4, Enabled: true, Type: "l2tp", Port: 1701, Subnet: "10.60.0.1/24"}}

	cases := map[string][]string{
		"ppp":            {"pppoe-isp.conf", "nic-eth0", `user "user"`},
		"tunnel-clients": {"vpn-l2tp-ch2.conf", "lns = lns.example", "vpn-l2tp-ch2.ppp", "openconnect-ch3.conf"},
		"l2tp-servers":   {"vpn-l2tp-srv4.conf", "vpn-l2tp-srv4.ppp"},
	}
	active := ids(Active(cfg))
	for id, fragments := range cases {
		if !has(active, id) {
			t.Errorf("artifact %q not active: %v", id, active)
		}
		out, err := Render(id, cfg)
		if err != nil {
			t.Errorf("render %s: %v", id, err)
			continue
		}
		for _, fragment := range fragments {
			if !strings.Contains(out, fragment) {
				t.Errorf("render %s lacks %q:\n%s", id, fragment, out)
			}
		}
	}
	if out, _ := Render("ppp", cfg); strings.Contains(out, "nobody") {
		t.Errorf("disabled uplink rendered:\n%s", out)
	}
}

// Apply каналов IKEv2 и L2TP/IPsec пишет и конфигурацию демона charon;
// без неё артефакт показывал только часть применённого.
func TestTunnelClientsRenderCharonDaemonConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = []config.Channel{
		{ID: "l2", Index: 2, Enabled: true, Type: "l2tp", Config: map[string]any{"server": "lns.example", "username": "u", "password": "p", "ipsec": true, "preshared_key": "secret-psk"}},
		{ID: "ike", Index: 5, Enabled: true, Type: "ikev2", Config: map[string]any{"server": "ike.example", "username": "u", "password": "p"}},
	}
	out, err := Render("tunnel-clients", cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"netos-l2tp-ipsec-ch2-daemon.conf", "netos-ikev2-ch5", "strongswan.conf"} {
		if !strings.Contains(out, fragment) {
			t.Errorf("render lacks %q:\n%s", fragment, out)
		}
	}
	if strings.Count(out, "charon {") != 2 {
		t.Errorf("want two charon configs:\n%s", out)
	}
}

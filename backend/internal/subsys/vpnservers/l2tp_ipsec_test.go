package vpnservers

import (
	"encoding/base64"
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestL2TPIPsecSharesDaemonWithoutEAPDependency(t *testing.T) {
	cfg, ike := ikev2TestConfig()
	secret := "test-key-with-quote-\"-and-dollar-$"
	l2 := config.VPNServer{Type: "l2tp", Index: 8, Enabled: true, Config: map[string]any{"listen": "0.0.0.0", "ipsec": true, "preshared_key": secret}}
	cfg.VPNServers = append(cfg.VPNServers, l2)
	out, err := renderIPsecServers([]config.VPNServer{ike}, cfg, l2tpIPsecServers(cfg))
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"version = 2", "version = 1", "mode = transport", "local_ts = dynamic[udp/1701]", "auth = eap-radius", "auth = psk", "secret = 0s" + base64.StdEncoding.EncodeToString([]byte(secret))} {
		if !strings.Contains(string(out), part) {
			t.Fatalf("missing %q", part)
		}
	}
	if strings.Contains(string(out), secret) {
		t.Fatal("PSK interpolated into swanctl syntax")
	}
	if strings.Contains(string(renderIPsecUnit("conf", "daemon", false)), ikev2AuthUnit) || strings.Contains(string(renderIKEv2DaemonConfig("")), "eap-radius") {
		t.Fatal("L2TP-only depends on EAP")
	}
	if !strings.Contains(string(renderIPsecUnit("conf", "daemon", true)), ikev2AuthUnit) {
		t.Fatal("IKEv2 lost EAP dependency")
	}
	unit := renderL2TPUnit(l2, "test.conf")
	if !strings.Contains(unit, "ExecStartPre=/bin/sh test.conf.ipsec-guard") {
		t.Fatal("listener can start without transport guard")
	}
	l2.Config["ipsec"] = false
	if strings.Contains(renderL2TPUnit(l2, "test.conf"), "ExecStartPre") {
		t.Fatal("plain mode acquired IPsec dependency")
	}
}

func TestL2TPIPsecPPPAuthAndDNS(t *testing.T) {
	s := config.VPNServer{Index: 1}
	secured := renderL2TPPPP(s, config.L2TPServerConfig{IPsec: true, DNS: []string{"10.99.0.1", "1.1.1.1"}})
	for _, part := range []string{"require-mschap-v2\n", "ms-dns 10.99.0.1\n", "ms-dns 1.1.1.1\n"} {
		if !strings.Contains(secured, part) {
			t.Fatalf("missing %s", part)
		}
	}
	if !strings.Contains(renderL2TPPPP(s, config.L2TPServerConfig{}), "require-chap\n") {
		t.Fatal("legacy plain authentication changed")
	}
}

package channels

import (
	"encoding/base64"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"path/filepath"
	"strings"
	"testing"
)

func TestL2TPIPsecTransportAndPlaintextGuards(t *testing.T) {
	ch := config.Channel{Type: "l2tp", Index: 7, Name: "test", Config: map[string]any{"ipsec": true, "server": "vpn.example", "preshared_key": "test-secret"}}
	c, _ := ch.L2TPConfig()
	conf := string(renderL2TPIPsec(ch, c))
	for _, want := range []string{"version = 1", "mode = transport", "reqid = 70007", "dynamic[udp/20007]", "dynamic[udp/1701]", "start_action = trap|start", "secret = 0s" + base64.StdEncoding.EncodeToString([]byte(c.PresharedKey))} {
		if !strings.Contains(conf, want) {
			t.Fatal(want, conf)
		}
	}
	if strings.Contains(conf, c.PresharedKey) {
		t.Fatal("raw secret exposed")
	}
	unit := renderL2TPUnit(ch, filepath.Join("/state", "vpn-l2tp-ch7.conf"))
	for _, want := range []string{"Wants=network-online.target netos-l2tp-ipsec-ch7.service", "ExecStartPre=/bin/sh", "--initiate --child netos-l2tp-ch7"} {
		if !strings.Contains(unit, want) {
			t.Fatal(want, unit)
		}
	}
	if strings.Index(unit, "-guard.sh") > strings.Index(unit, "--initiate") {
		t.Fatal("guard after initiate")
	}
	guard := string(renderL2TPIPsecGuard(ch))
	for _, want := range []string{"--sport 20007 -m policy --dir out --pol none -j DROP", "--dport 20007 -m policy --dir in --pol none -j DROP", "-C OUTPUT", "-I OUTPUT 1"} {
		if !strings.Contains(guard, want) {
			t.Fatal(want, guard)
		}
	}
	daemonUnit := string(renderL2TPIPsecUnit(ch, "/state/client.conf", "/state/daemon.conf"))
	for _, want := range []string{"state deleteall reqid 70007", "policy deleteall dir out proto udp sport 20007 dport 1701", "policy deleteall dir in proto udp sport 1701 dport 20007"} {
		if !strings.Contains(daemonUnit, want) {
			t.Fatal("missing scoped kernel cleanup", want)
		}
	}
	if strings.Contains(daemonUnit, "xfrm state flush") || strings.Contains(daemonUnit, "xfrm policy flush") {
		t.Fatal("global IPsec cleanup")
	}
	ch.Config["ipsec"] = false
	if strings.Contains(renderL2TPUnit(ch, "/plain.conf"), "swanctl") {
		t.Fatal("plain channel invokes IPsec")
	}
	other := ch
	other.Index = 8
	if l2tpIPsecVICI(ch) == l2tpIPsecVICI(other) {
		t.Fatal("shared daemon socket")
	}
}
func BenchmarkL2TPIPsecRender(b *testing.B) {
	for _, n := range []int{1, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := config.L2TPChannelConfig{Server: "vpn.example", IPsec: true, PresharedKey: "test-key"}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for j := 1; j <= n; j++ {
					ch := config.Channel{Index: j}
					renderL2TPIPsec(ch, c)
					renderL2TPIPsecGuard(ch)
				}
			}
		})
	}
}

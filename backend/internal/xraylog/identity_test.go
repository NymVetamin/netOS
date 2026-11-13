package xraylog

import (
	"strings"
	"testing"
)

func TestValidIdentity(t *testing.T) {
	for _, protocol := range []string{"reality", "vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "socks", "http"} {
		if !ValidIdentity("Server_1.test-"+strings.Repeat("a", 50), protocol) {
			t.Fatal("valid identity rejected", protocol)
		}
	}
	for _, id := range []string{"", ".", "..", strings.Repeat("a", 65), "a b", "a\nb", "a\x00b", "%n", `a"b`, `a\b`, "сервер"} {
		if ValidIdentity(id, "socks") {
			t.Fatal("unsafe unit field accepted", id)
		}
	}
	for _, protocol := range []string{"", "SOCKS", "xray", "unknown", "socks\nExecStart=bad"} {
		if ValidIdentity("server", protocol) {
			t.Fatal("unknown protocol accepted", protocol)
		}
	}
}

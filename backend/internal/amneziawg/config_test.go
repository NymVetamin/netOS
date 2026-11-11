package amneziawg

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func nativeFixture() string {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	return "[Interface]\nPrivateKey = " + key + "\n" + (config.AmneziaWGOptions{Jc: 4, Jmin: 20, Jmax: 40, H1: "100-200", H2: "300", H3: "400", H4: "500", I1: "<r 8><t>"}).NativeParameters() + "[Peer]\nPublicKey = " + key + "\nPresharedKey = " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.0.0.9/24, 10.0.0.0/24\nPersistentKeepalive = 25\n"
}

func TestNativeParseAndIdempotentDelta(t *testing.T) {
	want, err := ParseNative(context.Background(), nativeFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Peers) != 1 || len(want.Peers[0].AllowedIPs) != 1 || want.Peers[0].AllowedIPs[0] != "10.0.0.0/24" {
		t.Fatal("prefix normalization failed")
	}
	if want.Device["private_key"][:2] != "28" || want.Device["private_key"][62:] != "6a" {
		t.Fatal("private key not normalized")
	}
	if got := Delta(want, want); got != "" {
		t.Fatalf("repeat would write %q", got)
	}
	initial := Delta(want, State{})
	if strings.Contains(initial, "replace_peers") || !strings.Contains(initial, "public_key=") || !strings.Contains(initial, "allowed_ip=10.0.0.0/24") {
		t.Fatal("wrong initial peer update")
	}
	live := State{Device: want.Device, Peers: []Peer{{Key: strings.Repeat("ff", 32), Values: map[string]string{}}}}
	delta := Delta(want, live)
	if !strings.Contains(delta, "public_key="+strings.Repeat("ff", 32)+"\nremove=true\n") {
		t.Fatal("stale peer retained")
	}
	changed := State{Device: want.Device, Peers: []Peer{{Key: want.Peers[0].Key, Values: map[string]string{"persistent_keepalive_interval": "26"}, AllowedIPs: want.Peers[0].AllowedIPs}}}
	delta = Delta(changed, want)
	if delta != "public_key="+want.Peers[0].Key+"\npersistent_keepalive_interval=26\n" {
		t.Fatalf("unrelated state changed: %s", delta)
	}
}

func TestNativeRejectsScriptsAndMalformedParameters(t *testing.T) {
	for _, change := range []struct{ from, to string }{
		{"Jc = 4", "PostUp = shutdown"}, {"Jc = 4", "Jc = 4\nJc = 5"},
		{"H1 = 100-200", "H1 = 300"}, {"Jc = 4", "Jc = 999999999"},
		{"192.0.2.1:51820", "192.0.2.1:0"}, {"PersistentKeepalive = 25", "PersistentKeepalive = 2-70000"},
		{"[Peer]", "[Interface]"}, {"AllowedIPs = 10.0.0.9/24, 10.0.0.0/24", "AllowedIPs = garbage"},
	} {
		if _, err := ParseNative(context.Background(), strings.Replace(nativeFixture(), change.from, change.to, 1)); err == nil {
			t.Fatalf("accepted %q", change.to)
		}
	}
}

func TestNativeOmittedSignaturesClearExistingValues(t *testing.T) {
	before, err := ParseNative(context.Background(), nativeFixture())
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseNative(context.Background(), strings.Replace(nativeFixture(), "I1 = <r 8><t>\n", "", 1))
	if err != nil {
		t.Fatal(err)
	}
	if got := Delta(after, before); got != "i1=\n" {
		t.Fatalf("clearing a signature must not retain it or change unrelated state: %q", got)
	}
	if got := Delta(after, after); got != "" {
		t.Fatalf("repeat writes: %q", got)
	}
}

func TestTelemetryContainsNoSecrets(t *testing.T) {
	state := State{Device: map[string]string{"private_key": "PRIVATE", "header_protection_key": "HEADER"}, Peers: []Peer{{Key: strings.Repeat("ab", 32), Values: map[string]string{"preshared_key": "PRESHARED", "last_handshake_time_sec": "3", "rx_bytes": "4", "tx_bytes": "5"}}}}
	for _, field := range []string{"status", "listen-port", "latest-handshakes", "endpoints", "transfer", "telemetry"} {
		var out strings.Builder
		if err := telemetry(&out, state, field); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"PRIVATE", "HEADER", "PRESHARED"} {
			if strings.Contains(out.String(), secret) {
				t.Fatal("secret in telemetry")
			}
		}
	}
	if err := telemetry(&strings.Builder{}, state, "dump"); err == nil {
		t.Fatal("secret dump allowed")
	}
}

func BenchmarkParseAndDelta(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			prefix := strings.Split(nativeFixture(), "[Peer]")[0]
			var text strings.Builder
			text.WriteString(prefix)
			for i := 0; i < n; i++ {
				key := make([]byte, 32)
				key[0] = byte(i)
				key[1] = byte(i >> 8)
				fmt.Fprintf(&text, "[Peer]\nPublicKey = %s\nAllowedIPs = 10.%d.%d.1/32\n", base64.StdEncoding.EncodeToString(key), i>>8, i&255)
			}
			raw := text.String()
			live, err := ParseNative(context.Background(), raw)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				want, err := ParseNative(context.Background(), raw)
				if err != nil {
					b.Fatal(err)
				}
				if delta := Delta(want, live); delta != "" {
					b.Fatal("unexpected change")
				}
			}
		})
	}
}

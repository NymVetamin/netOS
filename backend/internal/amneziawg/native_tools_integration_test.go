//go:build linux

package amneziawg_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

// This checks the actual native parser, not kernel support. Run in an empty
// network namespace: setconf must parse successfully and then fail on a missing
// interface. The same test can use an extracted official APT tool later.
func TestAmneziaWGNativeToolsContract(t *testing.T) {
	tool := os.Getenv("NETOS_AWG_TOOLS_BINARY")
	if tool == "" {
		t.Skip("requires native AmneziaWG tools and an isolated network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("run this test with unshare -n in an empty network namespace", err)
	}
	key := func(n uint64) string {
		var raw [32]byte
		binary.BigEndian.PutUint64(raw[:], n)
		return base64.StdEncoding.EncodeToString(raw[:])
	}
	full := map[string]any{
		"jc": 4, "jmin": 20, "jmax": 40,
		"s1": 16, "s2": 17, "s3": 18, "s4": 19,
		"h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800",
		"i1": "<r 8><t>", "i2": "<b 0x1234>", "i3": "<rc 4>", "i4": "<rd 4>", "i5": "<r 2>",
		"header_protection_key": key(33), "content_padding_addition": "12-24",
		"rekey_after_time": "120-180", "rekey_timeout": "5-10", "reject_after_time": "200-240",
		"keepalive_timeout": "10-15", "max_handshake_attempts": "10-20",
		"random_trailers": true, "disable_cookies": true, "persistent_keepalive": "20-30",
	}
	check := func(t *testing.T, text string, accepted bool) {
		t.Helper()
		file := filepath.Join(t.TempDir(), "native.conf")
		if err := os.WriteFile(file, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, tool, "setconf", "awgprobe", file)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil || err == nil {
			t.Fatalf("expected a bounded failure on a missing interface: %v", err)
		}
		parsed := strings.Contains(string(out), "Unable to modify interface:")
		if parsed != accepted || !accepted && !strings.Contains(string(out), "Configuration parsing error") {
			// Fixtures contain only generated test keys; never use live profiles here.
			t.Fatalf("native parser accepted=%v, want=%v: %s", parsed, accepted, out)
		}
	}
	for _, settings := range []struct {
		name    string
		options map[string]any
	}{{"defaults", nil}, {"full31", full}, {"cleared", map[string]any{}}} {
		t.Run(settings.name, func(t *testing.T) {
			ch := config.Channel{ID: "test", Index: 1, Type: "amneziawg", Mode: "tun", Config: map[string]any{
				"address": "10.44.0.2/32", "private_key": key(1), "peer_public_key": key(2),
				"endpoint": "192.0.2.1:51820", "allowed_ips": []string{"0.0.0.0/0"}, "amnezia": settings.options,
			}}
			text, err := channels.RenderWireGuard(ch)
			if err != nil {
				t.Fatal(err)
			}
			check(t, text, true)
			check(t, strings.Replace(text, "[Interface]\n", "[Interface]\nPostUp = false\n", 1), false)
			for _, n := range []int{0, 10, 1000} {
				t.Run(fmt.Sprint(n), func(t *testing.T) {
					server := config.VPNServer{ID: "test", Index: 1, Type: "amneziawg", Subnet: "10.9.0.1/16", Port: 51820,
						Config: map[string]any{"private_key": key(1), "amnezia": settings.options}}
					for i := 0; i < n; i++ {
						server.Peers = append(server.Peers, config.VPNPeer{ID: fmt.Sprint(i), Enabled: true,
							Address: fmt.Sprintf("10.9.%d.%d", (i+2)/256, (i+2)%256), Credentials: map[string]string{"public_key": key(uint64(i + 2))}})
					}
					for repeat := 0; repeat < 3; repeat++ {
						start := time.Now()
						text, err := vpnservers.RenderWireGuard(server)
						if err != nil {
							t.Fatal(err)
						}
						check(t, text, true)
						t.Logf("render+write+native parse: peers=%d bytes=%d elapsed=%s", n, len(text), time.Since(start))
					}
				})
			}
		})
	}
	// The native parser accepts both inputs, but this is NOT a value roundtrip:
	// upstream type.c narrows to uint16. Kernel readback is a separate gate.
	for _, value := range []string{"65535", "65536"} {
		t.Run("timer_"+value, func(t *testing.T) {
			check(t, "[Interface]\nPrivateKey = "+key(1)+"\nRekeyAfterTime = "+value+"\n", true)
		})
	}
}

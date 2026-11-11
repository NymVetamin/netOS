//go:build linux

package amneziawg_test

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// This gate deliberately tests desired semantics, including settings reset.
// A source-built test module does not prove the official APT package works.
func TestAmneziaWGNativeKernelContract(t *testing.T) {
	if os.Getenv("NETOS_AWG_KERNEL_TEST") != "1" {
		t.Skip("requires disposable Linux kernel test host")
	}
	tool := os.Getenv("NETOS_AWG_TOOLS_BINARY")
	if tool == "" {
		t.Fatal("missing official native tool")
	}
	links, err := net.Interfaces()
	if err != nil || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("requires empty network namespace", err)
	}
	run := func(t *testing.T, name string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
		return string(out)
	}
	create := func(t *testing.T) {
		run(t, "ip", "link", "add", "awgprobe", "type", "amneziawg")
		t.Cleanup(func() { run(t, "ip", "link", "delete", "awgprobe") })
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	apply := func(t *testing.T, parameters string) {
		t.Helper()
		file := filepath.Join(t.TempDir(), "native.conf")
		if err := os.WriteFile(file, []byte("[Interface]\nPrivateKey = "+key+"\n"+parameters), 0600); err != nil {
			t.Fatal(err)
		}
		run(t, tool, "syncconf", "awgprobe", file)
	}
	t.Run("generated_defaults", func(t *testing.T) {
		create(t)
		apply(t, (config.AmneziaWGOptions{}).NativeParameters())
	})
	t.Run("protection_clear", func(t *testing.T) {
		create(t)
		options := config.AmneziaWGOptions{S1: 16, S2: 17, S3: 18, S4: 19, HeaderProtectionKey: key}
		apply(t, options.NativeParameters())
		options.HeaderProtectionKey = ""
		apply(t, options.NativeParameters())
		if strings.Contains(run(t, tool, "showconf", "awgprobe"), "HeaderProtectionKey") {
			t.Fatal("cleared header protection key remains enabled")
		}
	})
	t.Run("signature_clear", func(t *testing.T) {
		create(t)
		// Omit the key entirely to test signatures independently of key reset.
		apply(t, "I1 = <r 8>\n")
		apply(t, "")
		if strings.Contains(run(t, tool, "showconf", "awgprobe"), "I1 =") {
			t.Fatal("omitted signature remains configured")
		}
	})
	t.Run("timer_roundtrip", func(t *testing.T) {
		create(t)
		apply(t, "RekeyAfterTime = 65536\n")
		if got := strings.TrimSpace(run(t, tool, "show", "awgprobe", "rekey-after-time")); got != "65536" {
			t.Fatalf("timer silently changed: got %s, want 65536", got)
		}
	})
}

package channels

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenConnectScriptRespectsConfiguredMTU(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("executes the Linux connection script")
	}
	for _, reason := range []string{"connect", "reconnect"} {
		for _, tc := range []struct {
			name, negotiated, want string
			configured             int
		}{
			{"server larger", "1434", "1280", 1280},
			{"server smaller", "1200", "1200", 1280},
			{"server equal", "1280", "1280", 1280},
			{"server omitted", "", "1280", 1280},
			{"server zero", "0", "1280", 1280},
			{"default cap", "1500", "1400", 0},
		} {
			t.Run(reason+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "ip"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("/bin/sh")
				cmd.Stdin = strings.NewReader(renderOpenConnectScript(tc.configured))
				cmd.Env = []string{"PATH=" + dir, "reason=" + reason, "TUNDEV=qa-tun", "INTERNAL_IP4_ADDRESS=192.0.2.2", "INTERNAL_IP4_MTU=" + tc.negotiated}
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("script failed: %v: %s", err, out)
				}
				want := "link set dev qa-tun mtu " + tc.want + " up\n"
				if !strings.HasPrefix(string(out), want) {
					t.Fatalf("got %q, expected first command %q", out, want)
				}
			})
		}
	}
}

package vpnservers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestL2TPPreUpWaitsForExactListenerWithoutRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executes the generated Linux PPP hook")
	}
	for _, tc := range []struct {
		name                      string
		selected, enabled, active bool
		iface, address            string
		readyAt, wantPolls        int
	}{
		{"cold connect", true, true, true, "ppp-srv30", "10.99.1.1", 3, 3},
		{"reconnect", true, true, true, "ppp-srv30", "10.99.1.1", 1, 1},
		{"unselected", false, true, true, "ppp-srv30", "10.99.1.1", 3, 0},
		{"disabled", true, false, true, "ppp-srv30", "10.99.1.1", 3, 0},
		{"stopped", true, true, false, "ppp-srv30", "10.99.1.1", 3, 0},
		{"other interface", true, true, true, "ppp-srv31", "10.99.1.1", 3, 0},
		{"other address", true, true, true, "ppp-srv30", "10.99.2.1", 3, 0},
		{"unavailable listener", true, true, true, "ppp-srv30", "10.99.1.1", 0, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config.Config{}
			cfg.Samba.Enabled = tc.enabled
			if tc.selected {
				cfg.Samba.VPNs = []string{"l2tp"}
			}
			server := config.VPNServer{ID: "l2tp", Index: 30, Enabled: true, Subnet: "10.99.1.1/24"}
			active := "1"
			if tc.active {
				active = "0"
			}
			files := map[string]string{
				"systemctl": "#!/bin/sh\necho \"$*\" >> \"$DIR/calls\"\n[ \"$1\" = is-active ] || exit 99\nexit " + active + "\n",
				"ss":        "#!/bin/sh\nn=0; test ! -f \"$DIR/count\" || n=$(cat \"$DIR/count\")\nn=$((n+1)); echo $n > \"$DIR/count\"\necho 'LISTEN 0 50 10.99.1.10:445 0.0.0.0:*'\nif [ \"$READY\" -gt 0 ] && [ $n -ge \"$READY\" ]; then echo 'LISTEN 0 50 10.99.1.1:445 0.0.0.0:*'; fi\n",
				"hook":      string(renderL2TPPreUp(server, cfg)),
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 13*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(dir, "hook"), tc.iface, "unused", "0", tc.address)
			cmd.Env = append(os.Environ(), "PATH="+dir+":/usr/bin:/bin", "DIR="+dir, fmt.Sprintf("READY=%d", tc.readyAt))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("VPN hook failed: %v %s", err, out)
			}
			count, _ := os.ReadFile(filepath.Join(dir, "count"))
			if tc.wantPolls >= 0 {
				want := fmt.Sprint(tc.wantPolls)
				if tc.wantPolls == 0 {
					want = ""
				}
				if strings.TrimSpace(string(count)) != want {
					t.Fatalf("polls=%q want=%q", count, want)
				}
			} else if len(count) == 0 {
				t.Fatal("missing listener was not observed")
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
			if strings.Contains(string(calls), "restart") {
				t.Fatalf("hook restarted service: %s", calls)
			}
		})
	}
}

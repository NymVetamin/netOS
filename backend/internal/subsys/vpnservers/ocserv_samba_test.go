package vpnservers

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOcservConnectRepairsOnlyMissingSelectedSambaListener(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executes the generated Linux hook")
	}
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock required")
	}
	for _, tc := range []struct {
		name                                              string
		selected, enabled, active, listening, wantRestart bool
	}{
		{"first connection", true, true, true, false, true},
		{"next connection", true, true, true, true, false},
		{"unselected VPN", false, true, true, false, false},
		{"disabled Samba", true, false, true, false, false},
		{"stopped Samba", true, true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, server := ocservConfig()
			cfg.Samba.Enabled = tc.enabled
			if tc.selected {
				cfg.Samba.VPNs = []string{server.ID}
			}
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			active := "1"
			if tc.active {
				active = "0"
			}
			systemctl := "#!/bin/sh\nif [ \"$1\" = is-active ]; then exit " + active + "; fi\nprintf '%s\\n' \"$*\" >> \"$CALLS\"\n"
			ss := "#!/bin/sh\n"
			if tc.listening {
				ss += "echo 'LISTEN 0 50 10.30.0.1:445 0.0.0.0:*'\n"
			}
			for name, body := range map[string]string{"systemctl": systemctl, "ss": ss} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			hook := string(renderOcservConnect(server, cfg))
			hook = strings.ReplaceAll(hook, "/run/netos-ocserv-srv3/samba-connect.lock", filepath.Join(dir, "lock"))
			path := filepath.Join(dir, "hook")
			if err := os.WriteFile(path, []byte(hook), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/sh", path)
			cmd.Env = append(os.Environ(), "PATH="+dir+":/usr/bin:/bin", "REASON=connect", "CALLS="+log)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("hook blocks VPN: %v %s", err, out)
			}
			calls, _ := os.ReadFile(log)
			got := strings.Contains(string(calls), "try-restart netos-samba.service")
			if got != tc.wantRestart {
				t.Fatalf("restart=%v want=%v calls=%s", got, tc.wantRestart, calls)
			}
		})
	}
}

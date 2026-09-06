package manage

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallerLegacyReadiness(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native bash contract runs on Linux")
	}
	source := installerSource(t)
	start := strings.Index(source, "wait_netosd_ready() {")
	end := strings.Index(source, "\nrollback_and_cleanup() {")
	if start < 0 || end <= start {
		t.Fatal("readiness function not found")
	}
	for _, tc := range []struct {
		name, mode, pid, port, ping string
		marker, want                bool
	}{
		{"legacy healthy custom port", "legacy", "42", "9443", "good", false, true},
		{"legacy foreign listener", "legacy", "77", "9443", "good", false, false},
		{"legacy failed HTTPS", "legacy", "42", "9443", "error", false, false},
		{"legacy foreign response", "legacy", "42", "9443", "other", false, false},
		{"legacy invalid port", "legacy", "42", "0", "good", false, false},
		{"unknown old version", "unknown", "42", "9443", "good", false, false},
		{"modern needs marker", "modern", "42", "9443", "good", false, false},
		{"modern ready", "modern", "42", "9443", "error", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "ready")
			if tc.marker {
				if err := os.WriteFile(marker, []byte("1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			function := strings.ReplaceAll(source[start:end], "/run/netosd.ready", marker)
			script := `set -eu
BIN_PATH=fake_binary
fake_binary() {
 case "$1" in
  -h) if [ "$QA_MODE" = modern ]; then echo '  -panel-port'; fi ;;
  -version) if [ "$QA_MODE" = unknown ]; then echo 'netOS unknown'; else echo 'netOS v0.06'; fi ;;
  -render) printf '{\n "system": {\n  "panel": {\n   "port": %s,\n   "commit_timeout": 30\n  }\n },\n "vpn_servers": [{"port": 1234}]\n}\n' "$QA_PORT" ;;
 esac
}
systemctl() { if [ "$1" = show ]; then echo 42; fi; }
ss() { printf 'LISTEN 0 128 *:%s *:* users:(("netosd",pid=%s,fd=12))\n' "$QA_PORT" "$QA_PID"; }
curl() {
 [ "$QA_MODE" != modern ] || exit 90
 case "$*" in *"https://127.0.0.1:$QA_PORT/api/ping"*) ;; *) exit 91 ;; esac
 case "$QA_PING" in good) echo '{"ok":true,"service":"netos"}';; error) return 1;; other) echo '{"ok":true}';; esac
}
sleep() { :; }
` + function + "\nif wait_netosd_ready 1; then exit 0; else exit 1; fi\n"
			path := filepath.Join(dir, "readiness.sh")
			if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", path)
			cmd.Env = append(os.Environ(), "QA_MODE="+tc.mode, "QA_PID="+tc.pid, "QA_PORT="+tc.port, "QA_PING="+tc.ping)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("ready=%v want=%v: %v\n%s", err == nil, tc.want, err, out)
			}
			if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() != 1 {
				t.Fatalf("unexpected helper failure: %v\n%s", err, out)
			}
		})
	}
}

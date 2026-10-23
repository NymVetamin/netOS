package channels

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

type listenPortRunner struct {
	system.Runner
	output string
}

func (r listenPortRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "listen-port" {
		return r.output, nil
	}
	return r.Runner.Run(ctx, name, args...)
}

func TestWireGuardSyncPreservesPortAndStoredConfig(t *testing.T) {
	for _, tc := range []struct {
		port  string
		valid bool
	}{{"0", true}, {"51820\n", true}, {"65535", true}, {"", false}, {"65536", false}, {"-1", false}, {"123\n456", false}} {
		t.Run(tc.port, func(t *testing.T) {
			s, runner := newTestSubsystem(t)
			if err := os.MkdirAll(s.StateDir, 0700); err != nil {
				t.Fatal(err)
			}
			body, err := RenderWireGuard(channelConfig().Channels[1])
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.StateDir, "wg-ch1.conf")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			s.Runner = listenPortRunner{Runner: runner, output: tc.port}
			err = s.syncWireGuard(context.Background(), "wg-ch1", path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && !strings.Contains(string(runner.wgConfig), "ListenPort = "+strings.TrimSpace(tc.port)+"\n") {
				t.Fatal("live port absent from sync input")
			}
			if !tc.valid && len(runner.wgConfig) != 0 {
				t.Fatal("invalid port reached syncconf")
			}
			stored, err := os.ReadFile(path)
			if err != nil || string(stored) != body {
				t.Fatal("stored configuration changed")
			}
			files, err := filepath.Glob(filepath.Join(s.StateDir, ".wg-sync-*"))
			if err != nil || len(files) != 0 {
				t.Fatal("temporary secret file remained")
			}
		})
	}
}

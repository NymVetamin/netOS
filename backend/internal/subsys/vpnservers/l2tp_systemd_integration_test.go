package vpnservers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationL2TPStopLeavesNoFailedUnit(t *testing.T) {
	if os.Getenv("NETOS_L2TP_SYSTEMD_INTEGRATION") != "1" {
		t.Skip("requires root and systemd on a disposable Linux QA host")
	}
	server := config.VPNServer{Index: 987654}
	unit := l2tpUnitName(server)
	path := filepath.Join("/etc/systemd/system", unit)
	content := `[Unit]
Description=netOS QA L2TP stop fixture
[Service]
Type=simple
ExecStart=/bin/sh -c 'trap "exit 1" TERM; while :; do sleep 1; done'
[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	runner := system.NewExec()
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, "systemctl", "stop", unit)
		_ = os.Remove(path)
		_, _ = runner.Run(ctx, "systemctl", "daemon-reload")
		_, _ = runner.Run(ctx, "systemctl", "reset-failed", unit)
	})
	if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, "systemctl", "start", unit); err != nil {
		t.Fatal(err)
	}
	s := New(runner, t.TempDir())
	s.cleanupL2TP(ctx, server)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("L2TP unit file remains: %v", err)
	}
	out, err := runner.Run(ctx, "systemctl", "is-failed", unit)
	if err == nil || strings.TrimSpace(out) == "failed" {
		t.Fatalf("stopped L2TP unit remains failed: output=%q, err=%v", out, err)
	}
}

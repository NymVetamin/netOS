package manage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/netos-router/netos/internal/xraylog"
)

// This worker belongs to the Xray unit, not the maintenance queue. Holding the
// maintenance lock here would prevent applying configuration or stopping it.
func (m *Manager) runXrayLog(ctx context.Context, args []string) error {
	if len(args) != 2 || (args[0] != "run" && args[0] != "check") || !filepath.IsAbs(args[1]) {
		return fmt.Errorf("внутренняя команда Xray требует run/check и абсолютный путь конфигурации")
	}
	if err := m.requireRoot(); err != nil {
		return err
	}
	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	command := []string{"run"}
	if args[0] == "check" {
		command = append(command, "-test")
	}
	command = append(command, "-config", args[1])
	err := xraylog.Run(signalCtx, m.sys("/usr/local/bin/xray"), command, m.Out)
	if ctx.Err() == nil && signalCtx.Err() != nil && errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

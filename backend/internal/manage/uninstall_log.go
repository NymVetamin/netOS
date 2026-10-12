package manage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Outside LogDir: the uninstall transcript must survive even --no-backup.
const uninstallLogPath = "/var/log/netos-uninstall.log"

func (m *Manager) beginUninstallLog() (func(error), error) {
	path := m.sys(uninstallLogPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	out, stderr, run, output := m.Out, m.Err, m.Run, m.Output
	m.Out, m.Err = uninstallTee{f, out}, uninstallTee{f, stderr}
	log := func(message string, args ...any) {
		fmt.Fprintf(f, time.Now().UTC().Format(time.RFC3339)+" "+message+"\n", args...)
		_ = f.Sync()
	}
	log("Начало удаления netOS %s", m.Version)
	fmt.Fprintf(m.Out, "Журнал удаления: %s\n", uninstallLogPath)
	m.Run = func(ctx context.Context, c command) error {
		log("> %s %s", c.name, strings.Join(c.args, " "))
		err := run(ctx, c)
		log("< %s: %v", c.name, err)
		return err
	}
	m.Output = func(ctx context.Context, name string, args ...string) (string, error) {
		log("> %s %s", name, strings.Join(args, " "))
		text, err := output(ctx, name, args...)
		if name == "ip" || name == "ifquery" || name == "networkctl" || name == "systemctl" {
			log("< %s: %v\n%s", name, err, strings.TrimSpace(text))
		} else {
			log("< %s: %v", name, err)
		}
		return text, err
	}
	return func(result error) {
		log("Завершение удаления: %v", result)
		m.Out, m.Err, m.Run, m.Output = out, stderr, run, output
		_ = f.Close()
	}, nil
}

// A closed terminal must not turn a successful command into an I/O failure.
// The durable log is primary; diagnostic console writes are best effort.
type uninstallTee struct{ file, console io.Writer }

func (w uninstallTee) Write(p []byte) (int, error) {
	n, err := w.file.Write(p)
	if err != nil {
		return n, err
	}
	_, _ = w.console.Write(p)
	return n, nil
}

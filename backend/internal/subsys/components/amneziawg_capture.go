package components

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

func (s *Subsystem) amneziaCaptureDir() string { return filepath.Join(s.StateDir, "amneziawg-install") }

func (s *Subsystem) amneziaCapturePending() bool {
	for _, dir := range []string{s.amneziaCaptureDir(), s.amneziaCaptureDir() + "-complete"} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			return true
		}
	}
	return false
}

// Native dpkg events belong to this transaction, unlike a later whole-system
// inventory which could include another component's or administrator's packages.
func (s *Subsystem) beginAmneziaCapture(before map[string]bool) (system.Runner, error) {
	dir := s.amneziaCaptureDir()
	if err := os.MkdirAll(s.StateDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	cleanup := func() {
		_ = os.Remove(filepath.Join(dir, "before"))
		_ = os.Remove(filepath.Join(dir, "events"))
		_ = os.Remove(dir)
	}
	if err := system.WritePackageNames(filepath.Join(dir, "before"), before); err != nil {
		cleanup()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "events"), nil, 0600); err != nil {
		cleanup()
		return nil, err
	}
	return amneziaCaptureRunner{Runner: s.Packages.R, events: filepath.Join(dir, "events")}, nil
}

type amneziaCaptureRunner struct {
	system.Runner
	events string
}

func (r amneziaCaptureRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "apt-get" {
		for _, arg := range args {
			if arg == "install" {
				// StateDir is a path, never shell code. Quote embedded apostrophes.
				quoted := "'" + strings.ReplaceAll(r.events, "'", "'\"'\"'") + "'"
				args = append([]string{"-o", "Dpkg::Options::=--status-logger=cat >> " + quoted}, args...)
				break
			}
		}
	}
	return r.Runner.Run(ctx, name, args...)
}

func (s *Subsystem) finishAmneziaCapture() error {
	dir := s.amneziaCaptureDir()
	completed := dir + "-complete"
	cleanup := func() error {
		for _, name := range []string{"before", "events"} {
			if err := os.Remove(filepath.Join(completed, name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err := os.Remove(completed); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := cleanup(); err != nil {
		return err
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	before, err := system.ReadPackageNames(filepath.Join(dir, "before"))
	if err != nil {
		return err
	}
	owned, err := system.ReadPackageNames(s.amneziaRecord())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if owned == nil {
		owned = map[string]bool{}
	}
	events, err := os.ReadFile(filepath.Join(dir, "events"))
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(events), "\n") {
		body, ok := strings.CutPrefix(line, "status: ")
		if !ok {
			continue
		}
		name, state, ok := strings.Cut(body, ": ")
		if !ok {
			continue
		}
		switch state {
		case "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed":
			if name == "" || strings.ContainsAny(name, " \t/\r\n") || strings.HasPrefix(name, "-") {
				return fmt.Errorf("некорректное имя пакета в журнале AmneziaWG")
			}
			base, _, _ := strings.Cut(name, ":")
			if !before[name] && !before[base] {
				owned[name] = true
			}
		}
	}
	if err := system.WritePackageNames(s.amneziaRecord(), owned); err != nil {
		return err
	}
	// Preserve the journal if any commit step fails; recovery is idempotent.
	// Removing the directory is one rename, so an interrupted cleanup cannot
	// leave an active transaction missing one of its files.
	if err := os.Rename(dir, completed); err != nil {
		return err
	}
	return cleanup()
}

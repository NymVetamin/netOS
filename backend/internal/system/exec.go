// Package system — тонкая обёртка над вызовами внешних команд и systemd.
//
// Весь доступ к системе идёт через этот пакет, чтобы подсистемы оставались
// тестируемыми, а все выполняемые команды попадали в один журнал.
package system

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner выполняет команды. Подмена реализации позволяет тестировать
// подсистемы без настоящего Linux.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	RunInput(ctx context.Context, input string, name string, args ...string) (string, error)
}

// Exec — рабочая реализация Runner поверх os/exec.
type Exec struct {
	// Timeout по умолчанию для одной команды.
	Timeout time.Duration
	// PackageTimeout применяется к apt/dpkg: установка пакетов на слабом
	// устройстве закономерно занимает заметно больше сетевых команд.
	PackageTimeout time.Duration
	// OnCommand вызывается перед каждым запуском — используется для журнала.
	OnCommand func(name string, args []string)
}

func NewExec() *Exec {
	return &Exec{Timeout: 30 * time.Second, PackageTimeout: 15 * time.Minute}
}

func (e *Exec) Run(ctx context.Context, name string, args ...string) (string, error) {
	return e.RunInput(ctx, "", name, args...)
}

func (e *Exec) RunInput(ctx context.Context, input string, name string, args ...string) (string, error) {
	if e.OnCommand != nil {
		e.OnCommand(name, args)
	}
	timeout := e.Timeout
	if name == "apt-get" || name == "apt" || name == "dpkg" {
		timeout = e.PackageTimeout
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return stdout.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return stdout.String(), nil
}

// WriteFileAtomic пишет файл через временный файл и rename, чтобы демон,
// читающий конфиг в этот момент, никогда не увидел половину.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// CleanupAtomicTemps removes incomplete files left when a process was killed
// between CreateTemp and rename. It deliberately ignores directories and
// symlinks even when their names match the private temporary-file prefix.
func CleanupAtomicTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".tmp-") || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// FileChanged сообщает, отличается ли содержимое файла от данных. Позволяет
// не дёргать перезапуск демона, если конфиг не изменился.
func FileChanged(path string, data []byte) bool {
	existing, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	return !bytes.Equal(existing, data)
}

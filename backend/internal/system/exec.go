// Package system — тонкая обёртка над вызовами внешних команд и systemd.
//
// Весь доступ к системе идёт через этот пакет, чтобы подсистемы оставались
// тестируемыми, а все выполняемые команды попадали в один журнал.
package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if name == "systemctl" && input == "" {
		if out, err, handled := e.planUnitRead(ctx, args); handled {
			return out, err
		}
	}
	return e.runInput(ctx, input, name, args...)
}

func (e *Exec) runInput(ctx context.Context, input string, name string, args ...string) (string, error) {
	if e.OnCommand != nil {
		e.OnCommand(name, args)
	}
	timeout := e.Timeout
	packageCommand := name == "apt-get" || name == "apt" || name == "dpkg"
	if packageCommand {
		timeout = e.PackageTimeout
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	var policyFile *os.File
	if name == "apt-get" || name == "dpkg" {
		policyFile, _ = ctx.Value(daemonPolicyFileKey{}).(*os.File)
		if policyFile != nil && name == "apt-get" {
			// Keep the shared lock in dpkg and its maintainer scripts if the
			// calling netOS process is killed while the installation continues.
			args = append([]string{"-o", "APT::Keep-Fds::=3"}, args...)
		}
	}
	var inherited []*os.File
	if policyFile != nil {
		inherited = append(inherited, policyFile)
	}
	options, _ := ctx.Value(packageCommandOptionsKey{}).(*packageCommandOptions)
	if options != nil && name == options.name {
		args, inherited = options.prepare(args, inherited)
	}
	command := func() *exec.Cmd {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.ExtraFiles = inherited
		if name == "apt-cache" || name == "apt-get" || name == "dpkg" || name == "dpkg-query" {
			cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l")
			if options != nil && name == options.name {
				cmd.Env = append(cmd.Env, options.env...)
			}
		}
		if input != "" {
			cmd.Stdin = strings.NewReader(input)
		}
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		return cmd
	}

	var err error
	if dir := os.Getenv("NETOS_PACKAGE_CGROUP"); dir != "" {
		err = runManagedCommand(ctx, command, dir, packageCommand)
	} else {
		err = command().Run()
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if options != nil && name == options.name && ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
			err = errors.Join(err, ctx.Err())
		}
		return stdout.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	// A successful child exit does not guarantee that copying its output
	// finished before cancellation. Another process may have inherited a pipe.
	if err := ctx.Err(); err != nil {
		return stdout.String(), fmt.Errorf("%s: %w", name, err)
	}
	return stdout.String(), nil
}

// RestoreSymlinkAtomic replaces path with a symlink without following either target.
func RestoreSymlinkAtomic(path, target string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".netos-resolv-link-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := os.Symlink(target, tmpPath); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// WriteFileAtomic пишет файл через временный файл и rename, чтобы демон,
// читающий конфиг в этот момент, никогда не увидел половину.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return publishFileAtomic(path, data, perm, os.Rename)
}

func publishFileAtomic(path string, data []byte, perm os.FileMode, publish func(string, string) error) error {
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
	return publish(tmpName, path)
}

// WriteFileAtomicIfChanged preserves the inode and mtime when both content
// and permissions already match. A symlink or another non-regular target is
// always replaced atomically rather than followed.
func WriteFileAtomicIfChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	if AtomicFileMatches(path, data, perm) {
		return false, nil
	}
	if err := WriteFileAtomic(path, data, perm); err != nil {
		return false, err
	}
	return true, nil
}

// OpenSameRegular opens a reader only for the regular file identified by expected.
func OpenSameRegular(path string, expected os.FileInfo) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|atomicCompareFlags, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || !os.SameFile(info, expected)) {
		err = fmt.Errorf("file changed: %s", path)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// AtomicFileMatches checks the content and mode without following symlinks.
func AtomicFileMatches(path string, data []byte, perm os.FileMode) bool {
	return ownedFileMatches(path, data, perm, nil)
}

func ownedFileMatches(path string, data []byte, perm os.FileMode, owner os.FileInfo) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(data)) {
		return false
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != perm.Perm() {
		return false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|atomicCompareFlags, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || (owner != nil && !os.SameFile(owner, opened)) {
		return false
	}
	// Read one extra byte to detect growth after the size check.
	buf := make([]byte, len(data)+1)
	n, err := f.ReadAt(buf, 0)
	return err == io.EOF && bytes.Equal(buf[:n], data)
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

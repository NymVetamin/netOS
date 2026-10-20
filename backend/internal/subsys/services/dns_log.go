package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const dnsLogLimit = 4 << 20

// RotateDNSLog is called under the apply lock, so the writer cannot change
// between choosing the rotation method and reopening the file.
func RotateDNSLog(ctx context.Context, cfg *config.Config, runner system.Runner) error {
	var reopen func() error
	if cfg != nil && cfg.DNS.Enabled && cfg.DNS.QueryLog &&
		(cfg.DNS.Provider == "dnsmasq" || dnsFrontendNeeded(cfg)) {
		reopen = func() error {
			_, err := runner.Run(ctx, "systemctl", "kill", "--kill-whom=main", "--signal=SIGUSR2", "netos-dnsmasq.service")
			return err
		}
	}
	return rotateDNSLog("/var/log/netos/dns.log", dnsLogLimit, reopen)
}

func rotateDNSLog(path string, limit int64, reopen func() error) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("DNS log is not a regular file: %s", path)
	}
	if info.Size() < limit {
		return nil
	}
	// Three generations, in the existing netOS log directory (also covered by
	// backup/uninstall). Never follow archive symlinks.
	for n := 2; n >= 1; n-- {
		if err := os.Rename(fmt.Sprintf("%s.%d", path, n), fmt.Sprintf("%s.%d", path, n+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if reopen != nil {
		if err := os.Rename(path, path+".1"); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return errors.Join(err, os.Rename(path+".1", path))
		}
		closeErr := f.Close()
		if closeErr == nil {
			closeErr = reopen()
		}
		if closeErr != nil {
			// The old descriptor is still usable. Restore its pathname so a
			// failed signal does not leave logging in an abandoned archive.
			return errors.Join(closeErr, os.Remove(path), os.Rename(path+".1", path))
		}
		return nil
	}

	// dnsproxy v0.84.0 has no log-reopen signal. Keep its O_APPEND descriptor
	// valid using copytruncate, without restarting the resolver/cache. As with
	// logrotate copytruncate, writes in the copy/truncate window may be lost.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	archive, err := os.OpenFile(path+".1", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// A pre-existing oversized log must not cause an unbounded copy.
	start := max(int64(0), info.Size()-limit)
	_, copyErr := io.Copy(archive, io.NewSectionReader(f, start, info.Size()-start))
	if err := errors.Join(copyErr, archive.Close()); err != nil {
		_ = os.Remove(path + ".1")
		return err
	}
	return f.Truncate(0)
}

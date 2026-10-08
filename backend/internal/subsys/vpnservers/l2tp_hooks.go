package vpnservers

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// Debian 12's pppd lacks ip-pre-up-script. Both supported Debian versions
// dispatch /etc/ppp/ip-pre-up.d synchronously, passing the PPP arguments.
// Keep the script in generated state and own only this exact symlink.
func (s *Subsystem) l2tpPreUpLink(server config.VPNServer) string {
	return filepath.Join(s.PreUpDir, fmt.Sprintf("netos-l2tp-srv%d", server.Index))
}

func checkPreUpLink(path, target string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if got, err := os.Readlink(path); err != nil || got != target {
		return fmt.Errorf("PPP hook %s существует и не принадлежит netOS", path)
	}
	return nil
}

func removePreUpLink(path, target string) error {
	if got, err := os.Readlink(path); err == nil && got == target {
		return os.Remove(path)
	}
	return nil
}

// RemoveL2TPPreUpHooks is shared by reset/restore/uninstall. Regular files and
// links to other targets, even with a matching name, belong to somebody else.
func RemoveL2TPPreUpHooks(stateDir, preUpDir string) error {
	paths, err := filepath.Glob(filepath.Join(preUpDir, "netos-l2tp-srv*"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		index := strings.TrimPrefix(filepath.Base(path), "netos-l2tp-srv")
		n, err := strconv.Atoi(index)
		if err != nil || n < 0 || strconv.Itoa(n) != index {
			continue
		}
		target := filepath.Join(stateDir, "vpn-l2tp-srv"+index+".pre-up")
		if err := removePreUpLink(path, target); err != nil {
			return err
		}
	}
	return nil
}

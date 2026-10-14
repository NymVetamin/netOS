package vpnservers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const ikeArmorBegin = "\n# BEGIN netOS IKEv2\n"
const ikeArmorEnd = "# END netOS IKEv2\n"

var ikeArmorProfiles = []string{"usr.sbin.swanctl", "usr.sbin.charon-systemd"}

func writeIKEArmor(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("локальный профиль AppArmor %s не является обычным файлом", path)
		}
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeFile(path, data, mode)
}

func stripIKEArmor(data string) (string, bool, error) {
	start := strings.Index(data, ikeArmorBegin)
	if start < 0 {
		return data, false, nil
	}
	end := strings.Index(data[start:], ikeArmorEnd)
	if end < 0 {
		return "", false, fmt.Errorf("незавершённый блок AppArmor netOS IKEv2")
	}
	block := data[start : start+end+len(ikeArmorEnd)]
	return data[:start] + data[start+end+len(ikeArmorEnd):], strings.Contains(block, "# created-by-netos\n"), nil
}

// Keep the distribution policy and administrator additions. Grant only the
// netOS server's private configuration tree and its dedicated VICI socket.
func ikeArmorRule(profile, root string) string {
	if profile == "usr.sbin.swanctl" {
		return fmt.Sprintf("  %q r,\n  %q rw,\n", filepath.ToSlash(root)+"/**", "/run/netos-strongswan/charon.vici")
	}
	return fmt.Sprintf("  %q r,\n  %q rw,\n", filepath.ToSlash(filepath.Join(root, "strongswan.conf")), "/run/netos-strongswan/charon.vici")
}

func reloadIKEArmor(ctx context.Context, dir, profilesFile string, run func(context.Context, string, ...string) (string, error)) error {
	loaded, err := os.ReadFile(profilesFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, profile := range ikeArmorProfiles {
		binary := "/usr/sbin/" + strings.TrimPrefix(profile, "usr.sbin.")
		if !strings.Contains(string(loaded), binary+" (") {
			continue
		}
		path := filepath.Join(dir, profile)
		if _, err := run(ctx, "apparmor_parser", "-r", path); err != nil {
			return fmt.Errorf("перезагрузка AppArmor %s: %w", profile, err)
		}
	}
	return nil
}

func (s *Subsystem) ensureIKEArmor(ctx context.Context) error {
	for _, profile := range ikeArmorProfiles {
		policy, err := os.ReadFile(filepath.Join(s.AppArmorDir, profile))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !strings.Contains(string(policy), "<local/"+profile+">") {
			return fmt.Errorf("профиль AppArmor %s не подключает локальные разрешения", profile)
		}
		path := filepath.Join(s.AppArmorDir, "local", profile)
		original, err := os.ReadFile(path)
		created := os.IsNotExist(err)
		if err != nil && !created {
			return err
		}
		base, previouslyCreated, err := stripIKEArmor(string(original))
		if err != nil {
			return err
		}
		block := ikeArmorBegin
		if created || previouslyCreated {
			block += "# created-by-netos\n"
		}
		data := []byte(base + block + ikeArmorRule(profile, s.ikev2Paths().root) + ikeArmorEnd)
		if err := writeIKEArmor(path, data); err != nil {
			return err
		}
	}
	return reloadIKEArmor(ctx, s.AppArmorDir, s.AppArmorProfiles, s.Runner.Run)
}

// RemoveIKEv2AppArmor removes only our marked additions, including on uninstall
// after a failed apply has already removed the service unit and generated tree.
func RemoveIKEv2AppArmor(ctx context.Context, dir, profilesFile string, run func(context.Context, string, ...string) (string, error)) error {
	changed := false
	for _, profile := range ikeArmorProfiles {
		path := filepath.Join(dir, "local", profile)
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		base, created, err := stripIKEArmor(string(data))
		if err != nil {
			return err
		}
		if base == string(data) {
			continue
		}
		if created && base == "" {
			err = os.Remove(path)
		} else {
			err = writeIKEArmor(path, []byte(base))
		}
		if err != nil {
			return err
		}
		changed = true
	}
	if changed {
		return reloadIKEArmor(ctx, dir, profilesFile, run)
	}
	return nil
}

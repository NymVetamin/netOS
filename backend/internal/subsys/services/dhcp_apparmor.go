package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

var dhcpArmorDir = "/etc/apparmor.d"
var dhcpArmorProfiles = "/sys/kernel/security/apparmor/profiles"

const dhcpArmorBegin = "\n# BEGIN netOS DHCP\n"
const dhcpArmorEnd = "# END netOS DHCP\n"

type dhcpArmorPolicy struct {
	file, name, rules string
}

func dhcpArmorPolicies() []dhcpArmorPolicy {
	readConfig := func(path string) string {
		return fmt.Sprintf("  %q r,\n  %q r,\n", filepath.ToSlash(path),
			filepath.ToSlash(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".netos-validate-*")))
	}
	// Debian owns /var/lib/kea as _kea:_kea 0750. Our services run as root;
	// allow DAC traversal while retaining AppArmor's explicit file allowlist.
	leases := "  capability dac_override,\n  capability dac_read_search,\n" +
		fmt.Sprintf("  %q rw,\n", filepath.ToSlash(keaLeasePath)+"*")
	return []dhcpArmorPolicy{
		{"usr.sbin.dhcpd", "/usr/sbin/dhcpd", readConfig(iscConfPath) +
			fmt.Sprintf("  %q lrw,\n  %q lrw,\n", filepath.ToSlash(iscLeasePath)+"*",
				filepath.ToSlash(filepath.Join(filepath.Dir(iscConfPath), ".netos-dhcpd-leases-*")))},
		{"usr.sbin.kea-dhcp4", "kea-dhcp4", readConfig(keaConfPath) + leases +
			"  owner /run/kea/logger_lockfile rwk,\n"},
		{"usr.sbin.kea-lfc", "kea-lfc", leases},
	}
}

func stripDHCPArmor(data string) (string, bool, error) {
	start := strings.Index(data, dhcpArmorBegin)
	if start < 0 {
		return data, false, nil
	}
	end := strings.Index(data[start:], dhcpArmorEnd)
	if end < 0 {
		return "", false, fmt.Errorf("незавершённый блок AppArmor netOS DHCP")
	}
	block := data[start : start+end+len(dhcpArmorEnd)]
	return data[:start] + data[start+end+len(dhcpArmorEnd):], strings.Contains(block, "# created-by-netos\n"), nil
}

func writeDHCPArmor(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("локальный профиль AppArmor %s не является обычным файлом", path)
		}
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	_, err := writeManagedFile(path, data, mode)
	return err
}

func reloadDHCPArmor(ctx context.Context, dir, profiles string, policy dhcpArmorPolicy, run func(context.Context, string, ...string) (string, error)) error {
	loaded, err := os.ReadFile(profiles)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(loaded), "\n") {
		if strings.HasPrefix(line, policy.name+" (") || strings.HasPrefix(line, "/usr/sbin/"+strings.TrimPrefix(policy.file, "usr.sbin.")+" (") {
			if _, err := run(ctx, "apparmor_parser", "-r", filepath.Join(dir, policy.file)); err != nil {
				return fmt.Errorf("перезагрузка AppArmor %s: %w", policy.file, err)
			}
			break
		}
	}
	return nil
}

func ensureDHCPArmor(ctx context.Context, provider string, run func(context.Context, string, ...string) (string, error)) error {
	for _, policy := range dhcpArmorPolicies() {
		if (provider == "isc-dhcp-server") != (policy.file == "usr.sbin.dhcpd") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dhcpArmorDir, policy.file))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		path := filepath.Join(dhcpArmorDir, "local", policy.file)
		legacy := !strings.Contains(string(data), "<local/"+policy.file+">")
		if legacy {
			// Debian 12 Kea profiles have no local include. Keep the same
			// scoped block inside this known single-profile layout instead
			// of enabling unrelated, previously inactive local rules.
			if !legacyKeaProfile(string(data), policy) {
				return fmt.Errorf("профиль AppArmor %s не подключает локальные разрешения и имеет неподдерживаемую структуру", policy.file)
			}
			path = filepath.Join(dhcpArmorDir, policy.file)
		}
		original, err := os.ReadFile(path)
		created := os.IsNotExist(err)
		if err != nil && !created {
			return err
		}
		base, wasCreated, err := stripDHCPArmor(string(original))
		if err != nil {
			return err
		}
		block := dhcpArmorBegin
		if created || wasCreated {
			block += "# created-by-netos\n"
		}
		next := base + block + policy.rules + dhcpArmorEnd
		if legacy {
			end := strings.LastIndex(base, "\n}")
			if end < 0 || !legacyKeaProfile(base, policy) {
				return fmt.Errorf("повреждена структура профиля AppArmor %s", policy.file)
			}
			next = base[:end] + block + policy.rules + dhcpArmorEnd + base[end:]
		}
		if err := writeDHCPArmor(path, []byte(next)); err != nil {
			return err
		}
		// Also retry a previous failed reload when the file already matches.
		if err := reloadDHCPArmor(ctx, dhcpArmorDir, dhcpArmorProfiles, policy, run); err != nil {
			return err
		}
	}
	return nil
}

func legacyKeaProfile(data string, policy dhcpArmorPolicy) bool {
	if policy.file != "usr.sbin.kea-dhcp4" && policy.file != "usr.sbin.kea-lfc" {
		return false
	}
	header := "profile " + policy.name + " /usr/sbin/" + policy.name + " {"
	return strings.Contains(data, "\n"+header+"\n") &&
		strings.Count(data, "\nprofile ") == 1 &&
		strings.HasSuffix(strings.TrimSpace(data), "\n}")
}

// RemoveDHCPAppArmor preserves administrator additions and removes only our blocks.
func RemoveDHCPAppArmor(ctx context.Context, dir, profiles string, run func(context.Context, string, ...string) (string, error)) error {
	for _, policy := range dhcpArmorPolicies() {
		changed := false
		for _, path := range []string{filepath.Join(dir, "local", policy.file), filepath.Join(dir, policy.file)} {
			data, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			base, created, err := stripDHCPArmor(string(data))
			if err != nil {
				return err
			}
			if base == string(data) {
				continue
			}
			if created && base == "" {
				// Package includes can be mandatory; keep an empty local file.
				err = system.WriteFileAtomic(path, nil, 0o644)
			} else {
				err = writeDHCPArmor(path, []byte(base))
			}
			if err != nil {
				return err
			}
			changed = true
		}
		if !changed {
			continue
		}
		if err := reloadDHCPArmor(ctx, dir, profiles, policy, run); err != nil {
			return err
		}
	}
	return nil
}

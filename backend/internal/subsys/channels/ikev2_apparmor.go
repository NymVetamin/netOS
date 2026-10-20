package channels

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

const channelArmorBegin = "\n# BEGIN netOS IKEv2 channels\n"
const channelArmorEnd = "# END netOS IKEv2 channels\n"

var channelArmorFiles = []string{"usr.sbin.swanctl", "usr.sbin.charon-systemd"}

func stripChannelArmor(data string) (string, error) {
	start := strings.Index(data, channelArmorBegin)
	if start < 0 {
		return data, nil
	}
	end := strings.Index(data[start:], channelArmorEnd)
	if end < 0 {
		return "", fmt.Errorf("незавершённый блок AppArmor каналов IKEv2")
	}
	return data[:start] + data[start+end+len(channelArmorEnd):], nil
}

func channelArmorRules(profile, stateDir string) string {
	root := filepath.ToSlash(filepath.Join(stateDir, "netos-ikev2-ch[0-9]*"))
	rules := fmt.Sprintf("  %q r,\n  %q rw,\n", root+"/strongswan.conf", "/run/netos-ikev2-ch[0-9]*/charon.vici")
	if profile == "usr.sbin.swanctl" {
		rules += fmt.Sprintf("  %q r,\n  %q r,\n  %q r,\n", root+"/swanctl.conf", root+"/x509ca/", root+"/x509ca/ca.crt")
	}
	return rules
}

// Keep channel permissions separate from the incoming server and administrator
// policy. Empty local files must remain: distribution includes can be mandatory.
func syncChannelArmor(ctx context.Context, dir, profiles, stateDir string, enabled bool,
	run func(context.Context, string, ...string) (string, error)) error {
	loaded, err := os.ReadFile(profiles)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, profile := range channelArmorFiles {
		policyPath := filepath.Join(dir, profile)
		policy, err := os.ReadFile(policyPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if enabled && !strings.Contains(string(policy), "<local/"+profile+">") {
			return fmt.Errorf("профиль AppArmor %s не подключает локальные разрешения", profile)
		}
		path := filepath.Join(dir, "local", profile)
		mode := os.FileMode(0o644)
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("локальный профиль AppArmor %s не является обычным файлом", path)
			}
			mode = info.Mode().Perm()
		} else if !os.IsNotExist(err) {
			return err
		}
		original, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		base, err := stripChannelArmor(string(original))
		if err != nil {
			return err
		}
		if enabled {
			base += channelArmorBegin + channelArmorRules(profile, stateDir) + channelArmorEnd
		} else if base == string(original) {
			continue
		}
		if err := system.WriteFileAtomic(path, []byte(base), mode); err != nil {
			return err
		}
		binary := "/usr/sbin/" + strings.TrimPrefix(profile, "usr.sbin.")
		if strings.Contains(string(loaded), binary+" (") {
			// Retry reload even if an earlier attempt already wrote these rules.
			if _, err := run(ctx, "apparmor_parser", "-r", policyPath); err != nil {
				return fmt.Errorf("AppArmor канала IKEv2, профиль %s: %w", profile, err)
			}
		}
	}
	return nil
}

func RemoveIKEv2ChannelAppArmor(ctx context.Context, dir, profiles string,
	run func(context.Context, string, ...string) (string, error)) error {
	return syncChannelArmor(ctx, dir, profiles, "", false, run)
}

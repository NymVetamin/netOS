package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Профиль wireguard-tools в Ubuntu (с 24.10) разрешает wg читать только
// /etc/wireguard. netOS передаёт wg syncconf файлы из своего каталога
// состояния, и без дополнения применение каналов и серверов WireGuard
// отклонялось. В Debian такого профиля нет — там ничего не делается.
const (
	wireGuardArmorProfile = "wg"
	wireGuardArmorBegin   = "\n# BEGIN netOS WireGuard\n"
	wireGuardArmorEnd     = "# END netOS WireGuard\n"
	wireGuardArmorCreated = "# created-by-netos\n"
)

type armorRun func(context.Context, string, ...string) (string, error)

// EnsureWireGuardAppArmor даёт профилю wg право читать конфигурации netOS
// в stateDir. Профиль перезагружается только при изменении блока и в том
// режиме, в котором загружен: перевод в complain — решение администратора.
// При неудачной перезагрузке файл возвращается к прежнему виду, чтобы
// следующий вызов повторил попытку.
func EnsureWireGuardAppArmor(ctx context.Context, dir, profilesFile, stateDir string, run armorRun) error {
	policyPath := filepath.Join(dir, wireGuardArmorProfile)
	policy, err := os.ReadFile(policyPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.Contains(string(policy), "<local/"+wireGuardArmorProfile+">") {
		return fmt.Errorf("профиль AppArmor %s не подключает локальные разрешения", policyPath)
	}
	path := filepath.Join(dir, "local", wireGuardArmorProfile)
	original, existed, mode, err := readArmorLocal(path)
	if err != nil {
		return err
	}
	base, createdBefore, err := stripWireGuardArmor(original)
	if err != nil {
		return err
	}
	block := wireGuardArmorBegin
	if !existed || createdBefore {
		block += wireGuardArmorCreated
	}
	root := filepath.ToSlash(stateDir)
	block += fmt.Sprintf("  %q r,\n  %q r,\n  %q r,\n", root+"/wg-ch[0-9]*.conf", root+"/wg-srv[0-9]*.conf", root+"/.wg-sync-*")
	block += wireGuardArmorEnd
	want := base + block
	if existed && want == original {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := WriteFileAtomic(path, []byte(want), mode); err != nil {
		return err
	}
	if err := reloadWireGuardArmor(ctx, policyPath, profilesFile, run); err != nil {
		if existed {
			_ = WriteFileAtomic(path, []byte(original), mode)
		} else {
			_ = os.Remove(path)
		}
		return err
	}
	return nil
}

// RemoveWireGuardAppArmor убирает только блок netOS. Файл, созданный netOS,
// удаляется; существовавший до него остаётся, даже пустым.
func RemoveWireGuardAppArmor(ctx context.Context, dir, profilesFile string, run armorRun) error {
	path := filepath.Join(dir, "local", wireGuardArmorProfile)
	original, existed, mode, err := readArmorLocal(path)
	if err != nil || !existed {
		return err
	}
	base, created, err := stripWireGuardArmor(original)
	if err != nil || base == original {
		return err
	}
	if created && base == "" {
		err = os.Remove(path)
	} else {
		err = WriteFileAtomic(path, []byte(base), mode)
	}
	if err != nil {
		return err
	}
	if err := reloadWireGuardArmor(ctx, filepath.Join(dir, wireGuardArmorProfile), profilesFile, run); err != nil {
		// Без исходного блока повтор решил бы, что разрешения уже убраны,
		// хотя профиль ядра мог остаться прежним после ошибки загрузки.
		if restoreErr := WriteFileAtomic(path, []byte(original), mode); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("восстановление локального профиля AppArmor %s: %w", path, restoreErr))
		}
		return err
	}
	return nil
}

func readArmorLocal(path string) (data string, existed bool, mode os.FileMode, err error) {
	mode = 0o644
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "", false, mode, nil
	}
	if err != nil {
		return "", false, mode, err
	}
	if !info.Mode().IsRegular() {
		return "", false, mode, fmt.Errorf("локальный профиль AppArmor %s не является обычным файлом", path)
	}
	raw, err := os.ReadFile(path)
	return string(raw), true, info.Mode().Perm(), err
}

func stripWireGuardArmor(data string) (string, bool, error) {
	start := strings.Index(data, wireGuardArmorBegin)
	if start < 0 {
		return data, false, nil
	}
	end := strings.Index(data[start:], wireGuardArmorEnd)
	if end < 0 {
		return "", false, fmt.Errorf("незавершённый блок AppArmor netOS WireGuard")
	}
	block := data[start : start+end+len(wireGuardArmorEnd)]
	return data[:start] + data[start+end+len(wireGuardArmorEnd):], strings.Contains(block, wireGuardArmorCreated), nil
}

// reloadWireGuardArmor перезагружает профиль, если он загружен, сохраняя
// режим: «wg (complain)» перезагружается с -C.
func reloadWireGuardArmor(ctx context.Context, policyPath, profilesFile string, run armorRun) error {
	loaded, err := os.ReadFile(profilesFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(loaded), "\n") {
		if !strings.HasPrefix(line, wireGuardArmorProfile+" (") {
			continue
		}
		args := []string{"-r", policyPath}
		if strings.HasPrefix(line, wireGuardArmorProfile+" (complain)") {
			args = []string{"-r", "-C", policyPath}
		}
		if _, err := run(ctx, "apparmor_parser", args...); err != nil {
			return fmt.Errorf("перезагрузка AppArmor %s: %w", wireGuardArmorProfile, err)
		}
		return nil
	}
	return nil
}

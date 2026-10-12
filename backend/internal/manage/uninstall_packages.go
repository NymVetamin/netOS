package manage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

func (m *Manager) removeInstalledPackages(ctx context.Context) error {
	dir := m.sys(system.PackageOwnershipDir)
	initial, err := system.ReadPackageNames(filepath.Join(dir, "initial.txt"))
	if os.IsNotExist(err) {
		fmt.Fprintln(m.Err, "В этой старой установке нет учёта пакетов: пакеты APT сохранены, их происхождение нельзя подтвердить.")
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "pending")); !os.IsNotExist(err) {
		return fmt.Errorf("учёт установки пакетов не завершён; список сохранён в %s", dir)
	}
	owned, err := system.ReadPackageNames(filepath.Join(dir, "owned.txt"))
	if err != nil {
		return err
	}
	out, err := m.Output(ctx, "dpkg-query", "-W", "-f="+system.PackageInventoryFormat)
	if err != nil {
		return err
	}
	var packages []string
	foreignBase := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (!owned[f[0]] || initial[f[0]]) {
			foreignBase[strings.Split(f[0], ":")[0]] = true
		}
		if len(f) >= 2 && f[1] != "un" && f[1] != "pn" && owned[f[0]] && !initial[f[0]] {
			packages = append(packages, f[0])
		}
	}
	if len(packages) == 0 {
		return nil
	}
	sort.Strings(packages)
	// No global autoremove: dependencies are already in our explicit ledger.
	args := append([]string{"-o", "DPkg::Lock::Timeout=60", "-o", "APT::Get::AutomaticRemove=false", "purge", "-y"}, packages...)
	plan, err := m.Output(ctx, "apt-get", append([]string{"-s"}, args...)...)
	if err != nil {
		return fmt.Errorf("проверка удаления пакетов netOS: %w", err)
	}
	allowed := map[string]bool{}
	for _, name := range packages {
		allowed[name] = true
		if base := strings.Split(name, ":")[0]; !foreignBase[base] {
			allowed[base] = true
		}
	}
	for _, line := range strings.Split(plan, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[0] == "Inst" || ((f[0] == "Remv" || f[0] == "Purg") && !allowed[f[1]]) {
			return fmt.Errorf("удаление компонентов затронет сторонний пакет %s; удаление остановлено, данные сохранены", f[1])
		}
	}
	fmt.Fprintf(m.Out, "Удаляем пакеты, установленные netOS: %s\n", strings.Join(packages, ", "))
	if err := m.runEnv(ctx, []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}, "apt-get", args...); err != nil {
		return err
	}
	// A failed or incomplete purge must retain the recovery files and ledger.
	out, err = m.Output(ctx, "dpkg-query", "-W", "-f="+system.PackageInventoryFormat)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] != "un" && f[1] != "pn" && owned[f[0]] && !initial[f[0]] {
			return fmt.Errorf("пакет %s остался после удаления", f[0])
		}
	}
	return nil
}

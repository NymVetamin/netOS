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

// packagePurge is what uninstall would purge: ledger packages that netOS
// installed and that are still present.
type packagePurge struct {
	noLedger       bool
	packages       []string
	owned, initial map[string]bool
}

// planPackagePurge only reads: the ledger, dpkg and an apt simulation. Uninstall
// runs it before its first change, so a refusal leaves the router untouched,
// and again right before the purge, where the package state is current.
func (m *Manager) planPackagePurge(ctx context.Context) (packagePurge, error) {
	dir := m.sys(system.PackageOwnershipDir)
	initial, err := system.ReadPackageNames(filepath.Join(dir, "initial.txt"))
	if os.IsNotExist(err) {
		return packagePurge{noLedger: true}, nil
	}
	if err != nil {
		return packagePurge{}, err
	}
	if _, err := os.Stat(filepath.Join(dir, "pending")); !os.IsNotExist(err) {
		return packagePurge{}, fmt.Errorf("учёт установки пакетов не завершён; список сохранён в %s", dir)
	}
	owned, err := system.ReadPackageNames(filepath.Join(dir, "owned.txt"))
	if err != nil {
		return packagePurge{}, err
	}
	out, err := m.Output(ctx, "dpkg-query", "-W", "-f="+system.PackageInventoryFormat)
	if err != nil {
		return packagePurge{}, err
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
	p := packagePurge{packages: packages, owned: owned, initial: initial}
	if len(packages) == 0 {
		return p, nil
	}
	sort.Strings(packages)
	plan, err := m.Output(ctx, "apt-get", append([]string{"-s"}, purgeArgs(packages)...)...)
	if err != nil {
		return packagePurge{}, fmt.Errorf("проверка удаления пакетов netOS: %w", err)
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
			return packagePurge{}, fmt.Errorf("удаление компонентов затронет сторонний пакет %s", f[1])
		}
	}
	return p, nil
}

// No global autoremove: dependencies are already in our explicit ledger.
func purgeArgs(packages []string) []string {
	return append([]string{"-o", "DPkg::Lock::Timeout=60", "-o", "APT::Get::AutomaticRemove=false", "purge", "-y"}, packages...)
}

func (m *Manager) removeInstalledPackages(ctx context.Context) error {
	p, err := m.planPackagePurge(ctx)
	if err != nil {
		return fmt.Errorf("%w; удаление остановлено, данные сохранены", err)
	}
	if p.noLedger {
		fmt.Fprintln(m.Err, "В этой старой установке нет учёта пакетов: пакеты APT сохранены, их происхождение нельзя подтвердить.")
		return nil
	}
	packages, owned, initial := p.packages, p.owned, p.initial
	if len(packages) == 0 {
		return nil
	}
	// The AmneziaWG module stays loaded after its files are purged; unload it
	// while modprobe can still find it. A module in use refuses, harmlessly.
	for _, name := range packages {
		if strings.Split(name, ":")[0] == "amneziawg-dkms" {
			_, _ = m.Output(ctx, "modprobe", "-r", "amneziawg")
			break
		}
	}
	fmt.Fprintf(m.Out, "Удаляем пакеты, установленные netOS: %s\n", strings.Join(packages, ", "))
	if err := m.runEnv(ctx, []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}, "apt-get", purgeArgs(packages)...); err != nil {
		return err
	}
	// A failed or incomplete purge must retain the recovery files and ledger.
	out, err := m.Output(ctx, "dpkg-query", "-W", "-f="+system.PackageInventoryFormat)
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

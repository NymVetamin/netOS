package components

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/releaseversion"
)

type PackageUpdate struct {
	UpdateAvailable bool   `json:"update_available"`
	Name            string `json:"name"`
	Installed       string `json:"installed"`
	Available       string `json:"available"`
}
type ComponentUpdate struct {
	release         *externalRelease
	Token           string          `json:"token,omitempty"`
	Installed       string          `json:"installed,omitempty"`
	Available       string          `json:"available,omitempty"`
	UpdateAvailable bool            `json:"update_available"`
	Packages        []PackageUpdate `json:"packages,omitempty"`
	Error           string          `json:"error,omitempty"`
}

type packageComparison struct {
	newer bool
	err   error
}

// CheckUpdates is an explicit, bounded operation, not part of readiness probes.
// dpkg and apt-cache each run once for the whole selected catalog.
func (s *Subsystem) CheckUpdates(ctx context.Context, ids ...string) (map[string]ComponentUpdate, error) {
	return s.checkUpdates(ctx, true, ids...)
}
func (s *Subsystem) checkUpdates(ctx context.Context, refresh bool, ids ...string) (map[string]ComponentUpdate, error) {
	s.Progress.Stage("", "Проверка установленных версий")
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	selected := func(id string) bool { return len(wanted) == 0 || wanted[id] }
	out, err := s.Runner.Run(ctx, "dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n")
	if err != nil {
		return nil, err
	}
	installed := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[1] == "ii" {
			installed[f[0]] = f[2]
		}
	}
	packages := map[string]bool{}
	complete := map[string]bool{}
	for _, info := range config.Catalog {
		if selected(info.ID) && !info.External && len(info.Packages) > 0 {
			all := true
			for _, p := range info.Packages {
				if installed[p] == "" {
					all = false
					break
				}
			}
			if !all {
				continue
			}
			complete[info.ID] = true
			for _, p := range info.Packages {
				packages[p] = true
			}
		}
	}
	var aptErr error
	candidates := map[string]string{}
	if len(packages) > 0 {
		if refresh {
			s.Progress.Stage("", "Проверка репозиториев Debian")
			_, aptErr = s.Runner.Run(ctx, "apt-get", "-o", "APT::Update::Error-Mode=any", "update")
		}
		if aptErr == nil {
			names := make([]string, 0, len(packages))
			for p := range packages {
				names = append(names, p)
			}
			sort.Strings(names)
			out, aptErr = s.Runner.Run(ctx, "apt-cache", append([]string{"policy"}, names...)...)
			if aptErr == nil {
				candidates = parsePackageCandidates(out)
			}
		}
	}
	result := map[string]ComponentUpdate{}
	comparisons := map[string]packageComparison{}
	for _, info := range config.Catalog {
		if !selected(info.ID) {
			continue
		}
		row := ComponentUpdate{}
		if info.External {
			s.Progress.Stage(info.ID, "Проверка последней версии")
			rel, ok := externalReleases[info.ID]
			if !ok || !externalOwned(rel) {
				continue
			}
			v, e := s.installedExternalVersion(ctx, rel)
			if e != nil {
				row.Error = e.Error()
				result[info.ID] = row
				continue
			}
			row.Installed = v
			latest, e := latestRelease(ctx, rel)
			if e != nil {
				row.Error = e.Error()
			} else {
				row.release = &latest
				row.Available = latest.Version
				cmp, known := releaseversion.Compare(latest.Version, v)
				row.UpdateAvailable = known && cmp > 0
			}
		} else {
			if !complete[info.ID] {
				continue
			}
			for _, p := range info.Packages {
				v := installed[p]
				if v == "" {
					continue
				}
				candidate := candidates[p]
				if candidate == "" && aptErr == nil {
					row.Error = fmt.Sprintf("нет доступной версии пакета %s в репозитории", p)
				}
				pkg := PackageUpdate{Name: p, Installed: v, Available: candidate}
				if candidate != "" && candidate != v {
					cmp, checked := comparisons[p]
					if !checked {
						_, e := s.Runner.Run(ctx, "dpkg", "--compare-versions", candidate, "gt", v)
						cmp.newer = e == nil
						var exitErr *exec.ExitError
						if e != nil && (!errors.As(e, &exitErr) || exitErr.ExitCode() != 1) {
							cmp.err = e
						}
						comparisons[p] = cmp
					}
					pkg.UpdateAvailable = cmp.newer
					row.UpdateAvailable = row.UpdateAvailable || cmp.newer
					if cmp.err != nil {
						row.Error = fmt.Sprintf("сравнение версии %s: %v", p, cmp.err)
					}
				}
				row.Packages = append(row.Packages, pkg)
			}
			if len(row.Packages) == 0 {
				continue
			}
			row.Installed = row.Packages[0].Installed
			row.Available = row.Packages[0].Available
			if aptErr != nil {
				row.Error = fmt.Sprintf("не удалось проверить репозиторий: %v", aptErr)
			}
		}
		data, _ := json.Marshal(row)
		row.Token = fmt.Sprintf("%x", sha256.Sum256(data))
		result[info.ID] = row
	}
	return result, nil
}

// Upgrade rechecks the chosen candidate before changing the installation. The
// caller serializes this operation with Apply and other package operations.
func (s *Subsystem) Upgrade(ctx context.Context, id, token string) error {
	var info config.ComponentInfo
	found := false
	for _, c := range config.Catalog {
		if c.ID == id {
			info = c
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("неизвестный компонент")
	}
	rows, err := s.checkUpdates(ctx, false, id)
	if err != nil {
		return err
	}
	row, ok := rows[id]
	if !ok || row.Error != "" || !row.UpdateAvailable || token == "" || row.Token != token {
		return fmt.Errorf("версии изменились или проверка не завершена; проверьте обновления ещё раз")
	}
	changed := info
	changed.Packages = nil
	for _, p := range row.Packages {
		if p.UpdateAvailable {
			changed.Packages = append(changed.Packages, p.Name)
		}
	}
	units, err := s.updateUnits(ctx, changed)
	if err != nil {
		return err
	}
	if info.External {
		rel := externalReleases[id]
		if !externalOwned(rel) {
			return fmt.Errorf("компонент не принадлежит netOS")
		}
		if row.release == nil {
			return fmt.Errorf("нет проверенных данных релиза")
		}
		resolved := *row.release
		backup := rel.Target + ".netos-rollback"
		existed, err := backupExternalTarget(rel.Target, backup)
		if err != nil {
			return err
		}
		if !existed {
			return fmt.Errorf("установленный компонент отсутствует")
		}
		err = s.installRelease(ctx, id, resolved)
		if err != nil {
			// Download, verification and extraction precede the atomic rename.
			// Failure here leaves the running version untouched.
			_ = os.Remove(backup)
			return err
		}
		if err == nil && !s.externalCurrent(ctx, resolved) {
			err = fmt.Errorf("установленная версия не совпадает с выбранной")
		}
		if err == nil {
			s.Progress.Stage(id, "Перезапуск служб")
			err = s.restartUpdateUnits(ctx, units)
		}
		if err != nil {
			s.Progress.Stage(id, "Возврат предыдущей версии")
			recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			defer cancel()
			if restoreErr := restoreExternalTarget(rel.Target, backup); restoreErr != nil {
				return fmt.Errorf("%v; восстановление: %w", err, restoreErr)
			}
			if restartErr := s.restartUpdateUnits(recoveryCtx, units); restartErr != nil {
				return fmt.Errorf("%v; запуск прежней версии: %w", err, restartErr)
			}
			return fmt.Errorf("обновление отменено, прежняя версия восстановлена: %w", err)
		}
		return os.Remove(backup)
	}
	if err := s.captureOriginalComponent(ctx, info); err != nil {
		return err
	}
	var versions []string
	for _, p := range row.Packages {
		if p.UpdateAvailable {
			versions = append(versions, p.Name+"="+p.Available)
		}
	}
	s.Progress.Stage(id, "Загрузка и установка пакетов")
	installErr := s.Packages.Upgrade(ctx, versions)
	// A failed APT transaction can still have replaced some files. Restore service
	// execution using what is installed, while retaining the package error.
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	for _, unit := range info.Units {
		installErr = errors.Join(installErr, s.Systemd.Disable(recoveryCtx, unit))
	}
	s.Progress.Stage(id, "Перезапуск служб")
	return errors.Join(installErr, s.restartUpdateUnits(recoveryCtx, units))
}

func parsePackageCandidates(out string) map[string]string {
	r := map[string]string{}
	name := ""
	for _, line := range strings.Split(out, "\n") {
		if line != "" && line[0] != ' ' && strings.HasSuffix(line, ":") {
			name = strings.TrimSuffix(line, ":")
			continue
		}
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "Candidate:" && f[1] != "(none)" && name != "" {
			r[name] = f[1]
		}
	}
	return r
}

// Only services that were active are restarted. Shared packages map to every
// affected catalog entry; updating ppp, for example, also affects PPPoE.
func (s *Subsystem) updateUnits(ctx context.Context, info config.ComponentInfo) ([]string, error) {
	patterns := append([]string(nil), info.RunUnits...)
	if info.ID == "xray" {
		patterns = append(patterns, "netos-socks.service")
	}
	if info.ID == "samba" {
		patterns = append(patterns, "netos-wsdd*.service")
	}
	pkgs := map[string]bool{}
	for _, p := range info.Packages {
		pkgs[p] = true
	}
	for _, other := range config.Catalog {
		if other.ID == info.ID {
			continue
		}
		for _, p := range other.Packages {
			if pkgs[p] {
				patterns = append(patterns, other.RunUnits...)
				break
			}
		}
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	out, err := s.Runner.Run(ctx, "systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--plain")
	if err != nil {
		return nil, err
	}
	var units []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		for _, pattern := range patterns {
			if match, _ := filepath.Match(pattern, f[0]); match {
				units = append(units, f[0])
				break
			}
		}
	}
	sort.Strings(units)
	return units, nil
}

func (s *Subsystem) restartUpdateUnits(ctx context.Context, units []string) error {
	var failures []error
	for _, unit := range units {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", unit); err != nil {
			failures = append(failures, fmt.Errorf("перезапуск %s: %w", unit, err))
		}
	}
	if len(units) > 0 {
		// Type=simple becomes active before the daemon parses its configuration.
		// Give immediate startup failures time to reach systemd before accepting.
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(append(failures, ctx.Err())...)
		case <-timer.C:
		}
	}
	for _, unit := range units {
		if out, err := s.Runner.Run(ctx, "systemctl", "is-active", unit); err != nil || strings.TrimSpace(out) != "active" {
			failures = append(failures, fmt.Errorf("служба %s не запустилась", unit))
		}
	}
	return errors.Join(failures...)
}

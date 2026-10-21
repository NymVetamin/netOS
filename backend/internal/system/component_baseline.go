package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This snapshot belongs to the host, not the netOS database. A reset or a
// failed Apply must never replace it with the already modified host state.
type ComponentBaseline struct {
	Version  int                        `json:"version"`
	Packages map[string]BaselinePackage `json:"packages"`
	Services map[string]BaselineService `json:"services"`
	Files    map[string]string          `json:"files"`            // relative artifact -> SHA256
	Absent   []string                   `json:"absent,omitempty"` // package config files absent before takeover
}

type BaselinePackage struct {
	Version string `json:"version"`
	Archive string `json:"archive"`
	Auto    bool   `json:"auto"`
}

type BaselineService struct {
	Enabled string `json:"enabled"`
	Active  string `json:"active"`
}

type BaselineComponent struct {
	ID       string
	Packages []string
	Units    []string
}

// Include administrator-created includes and runtime databases that dpkg does
// not list as conffiles but maintainer scripts can delete on purge.
var componentStatePaths = map[string][]string{
	"samba":           {"var/lib/samba"},
	"dnsmasq":         {"var/lib/misc/dnsmasq.leases"},
	"isc-dhcp-server": {"etc/default/isc-dhcp-server", "var/lib/dhcp/dhcpd.leases", "var/lib/dhcp/dhcpd.leases~"},
	"unbound":         {"var/lib/unbound"},
}

func componentSnapshotDir(ownershipDir string) string {
	return filepath.Join(ownershipDir, "original-components")
}

func artifactHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ReadComponentBaseline(ownershipDir string) (*ComponentBaseline, error) {
	return readComponentBaseline(ownershipDir, true)
}

func readComponentBaseline(ownershipDir string, verifyArtifacts bool) (*ComponentBaseline, error) {
	if ownershipDir == "" {
		return nil, nil
	}
	dir := componentSnapshotDir(ownershipDir)
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if os.IsNotExist(err) {
		return nil, nil
	} // legacy installation
	if err != nil {
		return nil, err
	}
	var b ComponentBaseline
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	if b.Version != 1 || b.Packages == nil || b.Files == nil {
		return nil, fmt.Errorf("неполный снимок исходных компонентов")
	}
	for name, hash := range b.Files {
		if name != filepath.Base(name) || name == "." || name == ".." {
			return nil, fmt.Errorf("недопустимый файл снимка")
		}
		if verifyArtifacts {
			actual, err := artifactHash(filepath.Join(dir, name))
			if err != nil || actual != hash {
				return nil, fmt.Errorf("повреждён файл исходных компонентов %s: %v", name, err)
			}
		}
	}
	for name, p := range b.Packages {
		if !packageNamePattern.MatchString(name) || p.Version == "" || b.Files[p.Archive] == "" {
			return nil, fmt.Errorf("неполный снимок пакета %s", name)
		}
	}
	for _, path := range b.Absent {
		if !strings.HasPrefix(path, "etc/") || filepath.ToSlash(filepath.Clean(path)) != path || strings.Contains(path, "\\") {
			return nil, fmt.Errorf("недопустимый путь исходного файла")
		}
	}
	return &b, nil
}

// CaptureComponentBaseline runs immediately before netOS takes over or purges
// a particular component. Only its own affected package files are recorded.
func CaptureComponentBaseline(ctx context.Context, r Runner, root, ownershipDir string, catalog []BaselineComponent) error {
	if ownershipDir == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(ownershipDir, "restore-components")); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	b, err := readComponentBaseline(ownershipDir, false)
	if err != nil {
		return err
	}
	if b == nil {
		b = &ComponentBaseline{Version: 1, Packages: map[string]BaselinePackage{}, Services: map[string]BaselineService{}, Files: map[string]string{}}
	}
	initial, err := ReadPackageNames(filepath.Join(ownershipDir, "initial.txt"))
	if os.IsNotExist(err) {
		return nil
	} // test/legacy installations without a ledger
	if err != nil {
		return err
	}
	needed := false
	for _, c := range catalog {
		for _, name := range c.Packages {
			if initial[name] && b.Packages[name].Version == "" {
				needed = true
			}
		}
	}
	if !needed {
		return nil
	}
	if _, err := ReadComponentBaseline(ownershipDir); err != nil {
		return err
	}
	out, err := r.Run(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n")
	if err != nil {
		return err
	}
	installed := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[2] == "ii" && initial[f[0]] {
			installed[f[0]] = f[1]
		}
	}
	autoOut, err := r.Run(ctx, "apt-mark", "showauto")
	if err != nil {
		return err
	}
	auto := map[string]bool{}
	for _, name := range strings.Fields(autoOut) {
		auto[name] = true
	}
	paths := map[string]bool{}
	var names []string
	for _, c := range catalog {
		present := false
		for _, name := range c.Packages {
			if version := installed[name]; version != "" && b.Packages[name].Version == "" {
				b.Packages[name] = BaselinePackage{Version: version, Auto: auto[name]}
				names = append(names, name)
				present = true
			}
		}
		if !present {
			continue
		}
		for _, path := range componentStatePaths[c.ID] {
			paths[path] = true
		}
		for _, unit := range c.Units {
			if _, exists := b.Services[unit]; exists {
				continue
			}
			enabled, _ := r.Run(ctx, "systemctl", "is-enabled", unit)
			active, _ := r.Run(ctx, "systemctl", "is-active", unit)
			b.Services[unit] = BaselineService{strings.TrimSpace(enabled), strings.TrimSpace(active)}
		}
	}
	dir := componentSnapshotDir(ownershipDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if len(names) > 0 {
		sort.Strings(names)
		// A private cache keeps the original binaries available even after the
		// distribution removes that version from its repositories.
		cache := filepath.Join(dir, "download")
		if err := os.MkdirAll(filepath.Join(cache, "partial"), 0700); err != nil {
			return err
		}
		args := []string{"-o", "DPkg::Lock::Timeout=60", "-o", "Dir::Cache::archives=" + cache, "--download-only", "--reinstall", "--no-remove", "--no-install-recommends", "-y", "install"}
		for _, name := range names {
			args = append(args, name+"="+b.Packages[name].Version)
		}
		if _, err := r.Run(ctx, "apt-get", args...); err != nil {
			return fmt.Errorf("сохранение исходных пакетов: %w", err)
		}
		debs, err := filepath.Glob(filepath.Join(cache, "*.deb"))
		if err != nil {
			return err
		}
		for _, deb := range debs {
			meta, err := r.Run(ctx, "dpkg-deb", "-f", deb, "Package", "Version")
			if err != nil {
				return err
			}
			var name, version string
			for _, line := range strings.Split(meta, "\n") {
				if strings.HasPrefix(line, "Package: ") {
					name = strings.TrimPrefix(line, "Package: ")
				}
				if strings.HasPrefix(line, "Version: ") {
					version = strings.TrimPrefix(line, "Version: ")
				}
			}
			p, ok := b.Packages[name]
			if !ok || p.Version != version || p.Archive != "" {
				continue
			}
			p.Archive = filepath.Base(deb)
			if err := os.Rename(deb, filepath.Join(dir, p.Archive)); err != nil {
				return err
			}
			b.Packages[name] = p
		}
		for _, name := range names {
			if b.Packages[name].Archive == "" {
				return fmt.Errorf("исходный пакет %s не сохранён", name)
			}
			conffiles, err := r.Run(ctx, "dpkg-query", "-W", "-f=${Conffiles}\n", name)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(conffiles, "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && strings.HasPrefix(f[0], "/etc/") {
					paths[strings.TrimPrefix(f[0], "/")] = true
					if strings.HasPrefix(f[0], "/etc/apparmor.d/") && filepath.Dir(f[0]) == "/etc/apparmor.d" {
						for _, dir := range []string{"local", "disable", "force-complain"} {
							paths["etc/apparmor.d/"+dir+"/"+filepath.Base(f[0])] = true
						}
					}
				}
			}
		}
		var existing []string
		if root == "" {
			root = "/"
		}
		for path := range paths {
			if _, err := os.Lstat(filepath.Join(root, path)); err == nil {
				existing = append(existing, path)
			} else if !os.IsNotExist(err) {
				return err
			} else if strings.HasPrefix(path, "etc/") && !strings.HasSuffix(path, ".d") {
				b.Absent = append(b.Absent, path)
			}
		}
		sort.Strings(existing)
		var roots []string
		for _, path := range existing {
			covered := false
			for _, parent := range roots {
				if strings.HasPrefix(path, parent+"/") {
					covered = true
					break
				}
			}
			if !covered {
				roots = append(roots, path)
			}
		}
		existing = roots
		if len(existing) > 0 {
			archive := "config-" + names[0] + ".tar"
			args := append([]string{"--acls", "--xattrs", "-cpf", filepath.Join(dir, archive), "-C", root, "--"}, existing...)
			if _, err := r.Run(ctx, "tar", args...); err != nil {
				return fmt.Errorf("сохранение исходных настроек: %w", err)
			}
			b.Files[archive] = ""
		}
		for _, name := range names {
			b.Files[b.Packages[name].Archive] = ""
		}
	}
	for name := range b.Files {
		if b.Files[name] != "" {
			continue
		}
		hash, err := artifactHash(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		b.Files[name] = hash
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, "state.json"), raw, 0600)
}

func RestoreComponentPackages(ctx context.Context, r Runner, root, ownershipDir string, b *ComponentBaseline) error {
	if b == nil || len(b.Packages) == 0 {
		return nil
	}
	dir := componentSnapshotDir(ownershipDir)
	if root == "" {
		root = "/"
	}
	restoreFiles := func() error {
		var configs []string
		for name := range b.Files {
			if strings.HasPrefix(name, "config-") && strings.HasSuffix(name, ".tar") {
				configs = append(configs, name)
			}
		}
		sort.Strings(configs)
		for _, name := range configs {
			if _, err := r.Run(ctx, "tar", "--acls", "--xattrs", "-xpf", filepath.Join(dir, name), "-C", root); err != nil {
				return err
			}
		}
		for _, path := range b.Absent {
			if err := os.Remove(filepath.Join(root, path)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("возврат отсутствовавшего файла %s: %w", path, err)
			}
		}
		return nil
	}
	// Restore config before postinst can start a stock service, and again after
	// maintainer scripts have run. Do not erase netOS --keep-data lease files.
	if err := restoreFiles(); err != nil {
		return err
	}
	out, err := r.Run(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n")
	if err != nil {
		return err
	}
	live := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[2] == "ii" {
			live[f[0]] = f[1]
		}
	}
	var archives, automatic, manual []string
	for name, p := range b.Packages {
		if live[name] != p.Version {
			archives = append(archives, filepath.Join(dir, p.Archive))
		}
		if p.Auto {
			automatic = append(automatic, name)
		} else {
			manual = append(manual, name)
		}
	}
	if len(archives) > 0 {
		sort.Strings(archives)
		release, err := holdDaemons()
		if err != nil {
			return err
		}
		defer release()
		args := append([]string{"-o", "DPkg::Lock::Timeout=60", "-o", "Dpkg::Options::=--force-confold", "--no-remove", "--allow-downgrades", "--no-install-recommends", "-y", "install"}, archives...)
		if _, err := r.Run(ctx, "apt-get", args...); err != nil {
			return fmt.Errorf("восстановление исходных пакетов: %w", err)
		}
		out, err := r.Run(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n")
		if err != nil {
			return err
		}
		restored := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && f[2] == "ii" {
				restored[f[0]] = f[1]
			}
		}
		for name, p := range b.Packages {
			if restored[name] != p.Version {
				return fmt.Errorf("исходный пакет %s версии %s не восстановлен", name, p.Version)
			}
		}
	}
	if err := restoreFiles(); err != nil {
		return err
	}
	for mode, names := range map[string][]string{"auto": automatic, "manual": manual} {
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		if _, err := r.Run(ctx, "apt-mark", append([]string{mode}, names...)...); err != nil {
			return err
		}
	}
	return nil
}

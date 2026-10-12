package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Kept outside the database and installer rollback: apt transactions cannot be
// rolled back by restoring the netOS database or the installer files.
const PackageOwnershipDir = "/var/lib/netos-package-state"
const PackageInventoryFormat = "${binary:Package}\t${db:Status-Abbrev}\n"

var packageNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$`)

func ReadPackageNames(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := map[string]bool{}
	for _, name := range strings.Fields(string(data)) {
		if !packageNamePattern.MatchString(name) {
			return nil, fmt.Errorf("invalid package name %q in %s", name, path)
		}
		result[name] = true
	}
	return result, nil
}

func PackageInventory(ctx context.Context, r Runner) (map[string]bool, error) {
	out, err := r.Run(ctx, "dpkg-query", "-W", "-f="+PackageInventoryFormat)
	if err != nil {
		return nil, err
	}
	result := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] != "un" && fields[1] != "pn" {
			if !packageNamePattern.MatchString(fields[0]) {
				return nil, fmt.Errorf("invalid dpkg package %q", fields[0])
			}
			result[fields[0]] = true // include residual configs and interrupted installations
		}
	}
	return result, nil
}

func WritePackageNames(path string, names map[string]bool) error {
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	sort.Strings(list)
	return WriteFileAtomic(path, []byte(strings.Join(list, "\n")+"\n"), 0600)
}

// A missing marker identifies an old installation, for which ownership cannot
// safely be inferred from the current package catalog alone.
func (p *Packages) beginPackageCapture(ctx context.Context) (func() error, error) {
	dir := p.OwnershipDir
	if dir == "" {
		return func() error { return nil }, nil
	}
	initial, err := ReadPackageNames(filepath.Join(dir, "initial.txt"))
	if os.IsNotExist(err) {
		return func() error { return nil }, nil
	}
	if err != nil {
		return nil, err
	}
	owned, err := ReadPackageNames(filepath.Join(dir, "owned.txt"))
	if os.IsNotExist(err) {
		owned = map[string]bool{}
	} else if err != nil {
		return nil, err
	}
	before, err := PackageInventory(ctx, p.R)
	if err != nil {
		return nil, err
	}
	pending := filepath.Join(dir, "pending")
	f, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("учёт предыдущей установки пакетов не завершён: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return func() error {
		after, err := PackageInventory(context.WithoutCancel(ctx), p.R)
		if err != nil {
			return err
		}
		for name := range after {
			if !before[name] && !initial[name] {
				owned[name] = true
			}
		}
		if err := WritePackageNames(filepath.Join(dir, "owned.txt"), owned); err != nil {
			return err
		}
		return os.Remove(pending)
	}, nil
}

func (e *Exec) PackageStateDir() string { return PackageOwnershipDir }

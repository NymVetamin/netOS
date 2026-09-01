package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type dnsUnitSnapshot struct {
	name    string
	active  bool
	enabled bool
}

type dnsTransition struct {
	m     *Manager
	files []blocklistFileSnapshot
	units []dnsUnitSnapshot
	armed bool
}

func snapshotDNSDomainTransition(ctx context.Context, m *Manager, cfg *config.Config) (*dnsTransition, error) {
	if !hasKernelDomainPolicies(cfg) || cfg.DNS.Provider == "dnsmasq" {
		return nil, nil
	}
	backendConf, backendUnit := unboundConfPath, unboundUnit
	paths := []string{dnsmasqConfPath, filepath.Join(systemdUnitDir, dnsmasqUnit)}
	if cfg.DNS.Provider == "dnsproxy" {
		backendConf, backendUnit = dnsproxyConfPath, dnsproxyUnit
		paths = append(paths, dnsproxyHostsPath)
	}
	paths = append(paths, backendConf, filepath.Join(systemdUnitDir, backendUnit))
	tx := &dnsTransition{m: m}
	for _, path := range paths {
		item := blocklistFileSnapshot{path: path}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			tx.files = append(tx.files, item)
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", path)
		}
		item.data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		item.exists, item.mode = true, info.Mode().Perm()
		tx.files = append(tx.files, item)
	}
	for _, unit := range []string{backendUnit, dnsmasqUnit} {
		active, _ := m.Dnsmasq.Runner.Run(ctx, "systemctl", "is-active", unit)
		enabled, _ := m.Dnsmasq.Runner.Run(ctx, "systemctl", "is-enabled", unit)
		tx.units = append(tx.units, dnsUnitSnapshot{
			name: unit, active: strings.TrimSpace(active) == "active", enabled: strings.TrimSpace(enabled) == "enabled",
		})
	}
	return tx, nil
}

func (tx *dnsTransition) Rollback() error {
	if tx == nil || !tx.armed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var failures []string
	for _, item := range tx.files {
		if item.exists {
			if err := system.WriteFileAtomic(item.path, item.data, item.mode); err != nil {
				failures = append(failures, item.path+": "+err.Error())
			}
		} else if err := os.Remove(item.path); err != nil && !os.IsNotExist(err) {
			failures = append(failures, item.path+": "+err.Error())
		}
	}
	run := func(args ...string) {
		if _, err := tx.m.Dnsmasq.Runner.Run(ctx, "systemctl", args...); err != nil && !missingSystemdUnit(err) {
			failures = append(failures, strings.Join(args, " ")+": "+err.Error())
		}
	}
	run("daemon-reload")
	for _, unit := range tx.units {
		if unit.enabled {
			run("enable", unit.name)
		} else {
			run("disable", unit.name)
		}
		if unit.active {
			run("restart", unit.name)
		} else {
			run("stop", unit.name)
			run("reset-failed", unit.name)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("DNS transition rollback: %s", strings.Join(failures, "; "))
	}
	return nil
}

func missingSystemdUnit(err error) bool {
	text := strings.ToLower(err.Error())
	for _, phrase := range []string{"does not exist", "not loaded", "no such file", "not found", "could not be found", "not-found"} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

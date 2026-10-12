package manage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

func TestUninstallPackageOwnershipAndAptFailures(t *testing.T) {
	for _, mode := range []string{"success", "foreign dependent", "apt failure", "incomplete purge", "pending", "multiarch"} {
		t.Run(mode, func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			dir := m.sys(system.PackageOwnershipDir)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			_ = system.WritePackageNames(filepath.Join(dir, "initial.txt"), map[string]bool{"curl": true})
			_ = system.WritePackageNames(filepath.Join(dir, "owned.txt"), map[string]bool{"curl": true, "unbound": true, "libnew:amd64": true, "tcpdump": true})
			if mode == "pending" {
				_ = os.WriteFile(filepath.Join(dir, "pending"), nil, 0600)
			}
			purged := false
			m.Output = func(_ context.Context, name string, args ...string) (string, error) {
				if name == "apt-get" {
					if mode == "foreign dependent" {
						return "Remv foreign-app [1]\n", nil
					}
					return "Purg unbound [1]\nPurg libnew [1]\nPurg tcpdump [1]\n", nil
				}
				if name == "dpkg-query" {
					out := "curl\tii \nforeign-app\tii \n"
					if mode == "multiarch" {
						out += "libnew:i386\tii \n"
					}
					if !purged || mode == "incomplete purge" {
						out += "unbound\tii \nlibnew:amd64\tii \ntcpdump\trc \n"
					}
					return out, nil
				}
				return "", nil
			}
			m.Run = func(_ context.Context, c command) error {
				if c.name == "apt-get" {
					joined := strings.Join(c.args, " ")
					if strings.Contains(joined, "curl") || strings.Contains(joined, "--autoremove") || !strings.Contains(joined, "libnew:amd64") {
						t.Fatalf("unsafe purge: %s", joined)
					}
					purged = true
					if mode == "apt failure" {
						return errors.New("apt failed")
					}
				}
				return nil
			}
			err := m.removeInstalledPackages(context.Background())
			if (err == nil) != (mode == "success") {
				t.Fatalf("err=%v", err)
			}
			if (mode == "foreign dependent" || mode == "pending" || mode == "multiarch") && purged {
				t.Fatal("unsafe purge executed")
			}
		})
	}
}

func TestFullUninstallKeepsRecoveryOnPurgeFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		m, out := testManager()
		sandbox(t, m)
		dir := m.sys(system.PackageOwnershipDir)
		_ = os.MkdirAll(dir, 0700)
		_ = system.WritePackageNames(filepath.Join(dir, "initial.txt"), map[string]bool{"curl": true})
		_ = system.WritePackageNames(filepath.Join(dir, "owned.txt"), map[string]bool{"unbound": true})
		for _, path := range []string{m.Binary, m.CLI, filepath.Join(m.StateDir, "marker")} {
			_ = os.MkdirAll(filepath.Dir(path), 0700)
			_ = os.WriteFile(path, []byte("keep"), 0600)
		}
		purged := false
		m.Output = func(_ context.Context, name string, args ...string) (string, error) {
			if name == "apt-get" {
				return "Purg unbound [1]\n", nil
			}
			if name == "dpkg-query" && !purged {
				return "unbound\tii \n", nil
			}
			return "", nil
		}
		m.Run = func(_ context.Context, c command) error {
			if c.name == "apt-get" {
				if _, err := os.Stat(m.Binary); err != nil {
					t.Fatal("binary deleted before purge")
				}
				if fail {
					return errors.New("apt failure")
				}
				purged = true
			}
			return nil
		}
		err := m.uninstall(context.Background(), true, false, false, true)
		if (err != nil) != fail {
			t.Fatalf("err=%v", err)
		}
		for _, path := range []string{m.Binary, m.CLI, filepath.Join(m.StateDir, "marker"), filepath.Join(dir, "owned.txt")} {
			_, err := os.Stat(path)
			if fail && err != nil || !fail && !os.IsNotExist(err) {
				t.Fatalf("unexpected artifact state %s: %v", path, err)
			}
		}
		if fail && strings.Contains(out.String(), "netOS удалён.") {
			t.Fatal("failed purge reported success")
		}
	}
}

package manage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

func TestKeepUnboundAcrossPackageRemoval(t *testing.T) {
	for _, mode := range []string{"success", "purge failure", "restore failure"} {
		t.Run(mode, func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			ledger := m.sys(system.PackageOwnershipDir)
			if err := os.MkdirAll(ledger, 0700); err != nil {
				t.Fatal(err)
			}
			_ = system.WritePackageNames(filepath.Join(ledger, "initial.txt"), map[string]bool{})
			_ = system.WritePackageNames(filepath.Join(ledger, "owned.txt"), map[string]bool{"unbound": true})
			root := m.sys("/var/lib/unbound")
			owned := map[string]string{
				"netos/root.key":         "RFC5011 current state",
				"netos/root.key.123-tmp": "pending update",
				"netos-root.key":         "legacy state",
			}
			for name, contents := range owned {
				path := filepath.Join(root, name)
				_ = os.MkdirAll(filepath.Dir(path), 0700)
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_ = os.WriteFile(filepath.Join(root, "root.key"), []byte("package-owned"), 0600)
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
				if c.name != "apt-get" {
					return nil
				}
				// The actual Debian 12 postrm removes the entire directory.
				if err := os.RemoveAll(root); err != nil {
					return err
				}
				purged = true
				if mode == "restore failure" {
					return os.WriteFile(root, []byte("block directory restoration"), 0600)
				}
				if mode == "purge failure" {
					return errors.New("apt failed after postrm")
				}
				return nil
			}
			err := m.removePackagesPreservingUnbound(context.Background(), true)
			if (err != nil) != (mode != "success") {
				t.Fatalf("unexpected result: %v", err)
			}
			if mode == "purge failure" {
				got, readErr := os.ReadFile(filepath.Join(root, "netos/root.key"))
				if readErr != nil || string(got) != owned["netos/root.key"] {
					t.Fatalf("purge error returned before restoring the anchor: %q, %v", got, readErr)
				}
			}
			snapshot := filepath.Join(m.StateDir, "uninstall-unbound.json")
			if mode == "restore failure" {
				if _, err := os.Stat(snapshot); err != nil {
					t.Fatalf("recovery copy lost: %v", err)
				}
				if err := os.Remove(root); err != nil {
					t.Fatal(err)
				}
			}
			// Also exercises a retry after an interrupted/failed restoration.
			if err := m.removePackagesPreservingUnbound(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			for name, want := range owned {
				got, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(got) != want {
					t.Fatalf("%s: got %q, %v", name, got, err)
				}
			}
			if _, err := os.Stat(snapshot); !os.IsNotExist(err) {
				t.Fatalf("completed snapshot retained: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "root.key")); !os.IsNotExist(err) {
				t.Fatalf("restored a package-owned file: %v", err)
			}
		})
	}
}

func TestKeepUnboundRejectsNonRegularStateBeforePurge(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.sys("/var/lib/unbound/netos/nested"), 0700); err != nil {
		t.Fatal(err)
	}
	m.Output = func(context.Context, string, ...string) (string, error) {
		t.Fatal("package operation started with unsaved state")
		return "", nil
	}
	if err := m.removePackagesPreservingUnbound(context.Background(), true); err == nil {
		t.Fatal("accepted unsupported state")
	}
}

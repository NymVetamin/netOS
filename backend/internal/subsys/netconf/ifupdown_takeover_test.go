package netconf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIfupdownTakeoverMissingMainAndChangedInterfaceSet(t *testing.T) {
	useTemporaryPaths(t)
	if _, err := takeOverIfupdown([]string{"eth0"}); err != nil {
		t.Fatal(err)
	}
	if err := RestoreIfupdown(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ifupdownMain); !os.IsNotExist(err) {
		t.Fatal("invented original main", err)
	}
	original := "auto eth0 spare\niface eth0 inet dhcp\niface spare inet dhcp\n"
	if err := os.WriteFile(ifupdownMain, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := takeOverIfupdown([]string{"eth0"}); err != nil {
		t.Fatal(err)
	}
	undo, err := takeOverIfupdown([]string{"spare"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(ifupdownMain)
	if !strings.Contains(string(data), "iface eth0 inet dhcp") || strings.Contains(string(data), "iface spare") {
		t.Fatalf("wrong ownership update: %s", data)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(ifupdownMain)
	if strings.Contains(string(data), "iface eth0") || !strings.Contains(string(data), "iface spare inet dhcp") {
		t.Fatalf("wrong ownership rollback: %s", data)
	}
	if err := RestoreIfupdown(""); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(ifupdownMain)
	if string(data) != original {
		t.Fatal("original backup replaced by intermediate state")
	}
}

func TestIfupdownContinuedDirectives(t *testing.T) {
	data := []byte("auto lo \\\n eth0 spare\niface eth0 inet dhcp\n    post-up echo one \\\n      two\nno-auto-down spare\niface spare inet manual\n    post-up echo keep \\\n      this\n")
	got, err := withoutManagedIfupdown(data, []string{"eth0"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "eth0") || strings.Contains(string(got), "two") || !strings.Contains(string(got), "auto lo spare\n") || !strings.Contains(string(got), "no-auto-down spare\n") || !strings.Contains(string(got), "post-up echo keep \\\n      this") {
		t.Fatalf("bad continued stanza migration: %s", got)
	}
}

func TestIfupdownTakeoverPreservesUnmanagedAcrossSwitchAndRestoresOnUninstall(t *testing.T) {
	useTemporaryPaths(t)
	original := "# Debian\nsource interfaces.d/*\nauto lo eth0 spare\niface lo inet loopback\nallow-hotplug eth0 spare\niface eth0 inet dhcp\n    hostname router\niface eth0 inet6 auto\n    accept_ra 1\niface spare inet static\n    address 192.0.2.2/24\n    post-up echo keep\n"
	if err := os.MkdirAll(ifupdownDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ifupdownMain, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}
	cfg := routerConfig()
	cfg.System.NetworkBackend = "ifupdown"
	r := newBackendUnitRunner()
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(ifupdownMain)
	for _, want := range []string{"auto lo spare", "allow-hotplug spare", "iface lo inet loopback", "iface spare inet static\n    address 192.0.2.2/24\n    post-up echo keep"} {
		if !strings.Contains(string(first), want) {
			t.Fatalf("lost unrelated input %q: %s", want, first)
		}
	}
	if strings.Contains(string(first), "iface eth0") || strings.Contains(string(first), "hostname router") {
		t.Fatalf("old stanza remains: %s", first)
	}
	journal, _ := os.ReadFile(ifupdownBackupPath)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(ifupdownMain)
	journalAgain, _ := os.ReadFile(ifupdownBackupPath)
	if string(first) != string(again) || string(journal) != string(journalAgain) {
		t.Fatal("repeated Apply changed input or original backup")
	}
	cfg.System.NetworkBackend = "netos"
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	retained, _ := os.ReadFile(ifupdownMain)
	if strings.Contains(string(retained), "iface eth0") {
		t.Fatal("backend switch restored competing DHCP")
	}
	if err := RestoreIfupdown(""); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(ifupdownMain)
	if string(restored) != original {
		t.Fatalf("lost original on backend change: %s", restored)
	}
	if _, err := os.Stat(ifupdownBackupPath); !os.IsNotExist(err) {
		t.Fatal("journal remains", err)
	}
}

func TestIfupdownTakeoverRollsBackOnStartOrVerificationFailure(t *testing.T) {
	for _, failure := range []string{"systemctl start networking.service", "ifquery -i", "systemctl mask systemd-networkd.service"} {
		t.Run(failure, func(t *testing.T) {
			useTemporaryPaths(t)
			original := "auto lo eth0\niface lo inet loopback\niface eth0 inet dhcp\n"
			if err := os.MkdirAll(filepath.Dir(ifupdownMain), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ifupdownMain, []byte(original), 0644); err != nil {
				t.Fatal(err)
			}
			r := &failingCommandRunner{base: newBackendUnitRunner(), fail: failure}
			if failure == "ifquery -i" {
				r.fail = "ifquery -i " + ifupdownMain + " --list --allow auto"
			}
			cfg := routerConfig()
			cfg.System.NetworkBackend = "ifupdown"
			if err := New(r, nil).Apply(context.Background(), cfg); err == nil {
				t.Fatal("injected failure ignored")
			}
			data, _ := os.ReadFile(ifupdownMain)
			if string(data) != original {
				t.Fatalf("original lost after failure: %s", data)
			}
			if _, err := os.Stat(ifupdownBackupPath); !os.IsNotExist(err) {
				t.Fatal("journal remains", err)
			}
		})
	}
}

func TestIfupdownNestedSourcesAndDirectory(t *testing.T) {
	useTemporaryPaths(t)
	if err := os.MkdirAll(ifupdownDir, 0755); err != nil {
		t.Fatal(err)
	}
	main := "source-directory interfaces.d\n"
	fragment := "source nested/input\n"
	nested := filepath.Join(ifupdownDir, "nested", "input")
	if err := os.MkdirAll(filepath.Dir(nested), 0755); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{ifupdownMain: main, filepath.Join(ifupdownDir, "uplink"): fragment, nested: "allow-hotplug eth0\niface eth0 inet dhcp\n", filepath.Join(ifupdownDir, "ignored.conf"): "iface eth0 inet static\n"} {
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	undo, err := takeOverIfupdown([]string{"eth0"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(ifupdownMain)
	if !strings.Contains(string(data), "source "+ifupdownPath) {
		t.Fatal("source-directory excludes .conf, explicit include missing")
	}
	data, _ = os.ReadFile(nested)
	if strings.Contains(string(data), "eth0") {
		t.Fatal("nested conflict remains")
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(nested)
	if !strings.Contains(string(data), "iface eth0 inet dhcp") {
		t.Fatal("nested original lost")
	}
}

func TestIfupdownRestorePreservesLaterEdits(t *testing.T) {
	useTemporaryPaths(t)
	if err := os.MkdirAll(filepath.Dir(ifupdownMain), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ifupdownMain, []byte("iface eth0 inet dhcp\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := takeOverIfupdown([]string{"eth0"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ifupdownMain, []byte("# later edit\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := RestoreIfupdown(""); err == nil {
		t.Fatal("later edit overwritten")
	}
	data, _ := os.ReadFile(ifupdownMain)
	if string(data) != "# later edit\n" {
		t.Fatal("later edit lost")
	}
	if _, err := os.Stat(ifupdownBackupPath); err != nil {
		t.Fatal("recovery backup lost", err)
	}
}

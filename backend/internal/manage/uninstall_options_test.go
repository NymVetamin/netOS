package manage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallBackupChoice(t *testing.T) {
	for _, tc := range []struct {
		name, input                     string
		flags                           []string
		backup, prompt, cancel, wantErr bool
	}{
		{name: "accept backup", input: "y\ny\n", backup: true, prompt: true},
		{name: "decline backup", input: "y\nn\n", prompt: true},
		{name: "default no backup", input: "y\n\n", prompt: true},
		{name: "cancel removal", input: "n\n", cancel: true},
		{name: "explicit backup", flags: []string{"--backup"}, input: "y\n", backup: true},
		{name: "explicit no backup", flags: []string{"--no-backup"}, input: "y\n"},
		{name: "automated backup", flags: []string{"--yes", "--backup"}, backup: true},
		{name: "automated no backup", flags: []string{"--yes", "--no-backup"}},
		{name: "missing choice", flags: []string{"--yes"}, wantErr: true},
		{name: "conflicting choice", flags: []string{"--yes", "--backup", "--no-backup"}, wantErr: true},
		{name: "keep data rollback", flags: []string{"--yes", "--keep-data"}},
		{name: "keep data explicit backup", flags: []string{"--yes", "--keep-data", "--backup"}, backup: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, out := testManager()
			sandbox(t, m)
			if err := os.MkdirAll(m.StateDir, 0700); err != nil {
				t.Fatal(err)
			}
			m.In = strings.NewReader(tc.input)
			backups, mutations := 0, 0
			m.Run = func(_ context.Context, c command) error {
				mutations++
				if c.name == "tar" {
					backups++
					for i, arg := range c.args {
						if arg == "-czf" {
							return os.WriteFile(c.args[i+1], nil, 0600)
						}
					}
				}
				return nil
			}
			for _, p := range []string{"/etc/bash_completion.d/netos", "/usr/share/bash-completion/completions/netos"} {
				path := m.sys(p)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("completion"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err := m.Execute(context.Background(), append([]string{"uninstall"}, tc.flags...))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
			if (backups == 1) != tc.backup || backups > 1 {
				t.Fatalf("backups=%d", backups)
			}
			if strings.Contains(out.String(), "Создать резервную копию перед удалением?") != tc.prompt {
				t.Fatalf("wrong prompt: %s", out)
			}
			if tc.cancel || tc.wantErr {
				if mutations != 0 {
					t.Fatalf("mutated before consent: %d", mutations)
				}
				return
			}
			if !strings.Contains(out.String(), "netOS удалён") {
				t.Fatalf("uninstall incomplete: %s", out)
			}
			for _, p := range []string{"/etc/bash_completion.d/netos", "/usr/share/bash-completion/completions/netos"} {
				if _, err := os.Stat(m.sys(p)); !os.IsNotExist(err) {
					t.Fatalf("completion left behind: %s %v", p, err)
				}
			}
		})
	}
}

func TestUninstallBackupFailureKeepsData(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	want := errors.New("backup failed")
	restarted := false
	m.Run = func(_ context.Context, c command) error {
		if c.name == "tar" {
			return want
		}
		if c.name == "systemctl" && strings.Join(c.args, " ") == "start netosd" {
			restarted = true
		}
		return nil
	}
	err := m.Execute(context.Background(), []string{"uninstall", "--yes", "--backup"})
	if !errors.Is(err, want) || !restarted || strings.Contains(out.String(), "netOS удалён") {
		t.Fatalf("err=%v restarted=%v out=%s", err, restarted, out)
	}
	if _, err := os.Stat(m.StateDir); err != nil {
		t.Fatal("data removed on backup failure", err)
	}
}

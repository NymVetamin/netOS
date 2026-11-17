//go:build linux

package eventlog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in: emits a test syslog record as nobody on a disposable host.
func TestSSHJournalLinuxTrustedOrigin(t *testing.T) {
	if os.Getenv("NETOS_JOURNAL_LINUX_TEST") != "1" {
		t.Skip("requires an authorized journald host and root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := func(name string, args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).Output()
		if err != nil {
			t.Fatalf("%s failed: %v", name, err)
		}
		return out
	}
	marker := fmt.Sprintf("netos-origin-test-%d", time.Now().UnixNano())
	run("runuser", "-u", "nobody", "--", "logger", "-t", "sshd", "Accepted publickey for netos_test from 192.0.2.1 port 1234 ssh2: "+marker)
	run("journalctl", "--sync")
	raw := run("journalctl", "--no-pager", "-o", "json", "--output-fields="+journalFields, "-n", "1", "--grep="+marker, "SYSLOG_IDENTIFIER=sshd")
	rec, err := parseRecord(raw)
	if err != nil || rec["_UID"] == "0" || rec["_UID"] == "" {
		t.Fatal("unprivileged source record or trusted UID missing")
	}
	l := New()
	j := &Journal{Log: l}
	j.Handle(ctx, raw, time.Now())
	page, _, _ := l.Since(Access, "", 0)
	if len(page.Events) != 0 {
		t.Fatal("unprivileged logger was accepted as SSH")
	}
	args := append([]string{"--no-pager", "-o", "json", "--output-fields=" + journalFields, "-n", "1", "--grep=" + marker}, journalMatches()...)
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	if err != nil {
		// journalctl --grep reports no matches with status 1 on systemd 257.
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || len(exit.Stderr) != 0 {
			t.Fatalf("filtered journal read failed: %v", err)
		}
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatal("production journal filter selected the unprivileged SSH imitation")
	}
	// The runner connects by SSH; preserve an actual daemon login, not a
	// privileged logger imitation. No source addresses are printed.
	raw = run("journalctl", "--no-pager", "-o", "json", "--output-fields="+journalFields, "-n", "1", "--grep=^Accepted ", "_UID=0", "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session")
	j.Handle(ctx, raw, time.Now())
	page, _, _ = l.Since(Access, "", 0)
	if len(page.Events) != 1 || page.Events[0].Source != "SSH" {
		t.Fatal("real SSH login was not retained")
	}
}

func TestJournalHistoryLinux(t *testing.T) {
	if os.Getenv("NETOS_JOURNAL_LINUX_TEST") != "1" {
		t.Skip("requires authorized journald host with a real SSH login")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l := New()
	l.Add(time.Now().Add(time.Hour), Access, Info, "panel", "newer panel event")
	first, _, _ := l.Since(Access, "", 0)
	j := &Journal{Log: l}
	j.refill(ctx)
	p, _, _ := l.Since(Access, first.Epoch, first.Latest)
	if !p.Reset || len(p.Events) < 2 || p.Events[0].Source != "panel" {
		t.Fatal("real journal history did not preserve/reset the newer panel event")
	}
	found := false
	for _, e := range p.Events {
		found = found || e.Source == "SSH"
	}
	if !found || j.Log != l || j.cursor == "" {
		t.Fatal("real SSH history or live log/cursor lost")
	}
}

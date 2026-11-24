package system

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAptInheritsPolicyFile(t *testing.T) {
	path := withTestPolicyPath(t)
	dir := t.TempDir()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("QA_POLICY", path)
	script := `#!/bin/sh
set -eu
test "$1" = -o && test "$2" = APT::Keep-Fds::=3
test /proc/self/fd/3 -ef "$QA_POLICY"
`
	if err := os.WriteFile(filepath.Join(dir, "apt-get"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := holdPackageDaemons(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := NewExec().Run(ctx, "apt-get", "install", "sample"); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonPolicyCrashRecovery(t *testing.T) {
	const childPath = "NETOS_TEST_POLICY_OWNER"
	if path := os.Getenv(childPath); path != "" {
		PolicyRCPath = path
		release, err := holdDaemons()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		release()
		return
	}
	path := withTestPolicyPath(t)
	start := func() func() {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonPolicyCrashRecovery$")
		cmd.Env = append(os.Environ(), childPath+"="+path)
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
		if line, err := bufio.NewReader(out).ReadString('\n'); line != "ready\n" || err != nil {
			t.Fatalf("holder: %q %v", line, err)
		}
		return func() {
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
		}
	}
	first, second := start(), start()
	first()
	if err := RecoverDaemonPolicy(); err != nil || !AtomicFileMatches(path, []byte(daemonPolicyScript), 0755) {
		t.Fatalf("startup touched a live holder: %v", err)
	}
	second()
	for range 2 {
		if err := RecoverDaemonPolicy(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{path, path + ".netos-owner"} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Fatalf("leftover %s: %v", name, err)
		}
	}
	start()()
	release, err := holdDaemons()
	if err != nil || !AtomicFileMatches(path, []byte(daemonPolicyScript), 0755) {
		t.Fatalf("retry did not acquire policy: %v", err)
	}
	release()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("retry left policy: %v", err)
	}
	start()()
	admin := filepath.Join(filepath.Dir(path), "replacement")
	if err := os.WriteFile(admin, []byte(daemonPolicyScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(admin, path); err != nil {
		t.Fatal(err)
	}
	if err := RecoverDaemonPolicy(); err != nil || !AtomicFileMatches(path, []byte(daemonPolicyScript), 0755) {
		t.Fatalf("identical administrator replacement lost: %v", err)
	}
}

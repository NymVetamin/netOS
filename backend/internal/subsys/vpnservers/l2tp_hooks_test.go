package vpnservers

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestL2TPHookOwnershipAndCleanup(t *testing.T) {
	state, hooks := t.TempDir(), t.TempDir()
	own := filepath.Join(hooks, "netos-l2tp-srv30")
	target := filepath.Join(state, "vpn-l2tp-srv30.pre-up")
	if err := checkPreUpLink(own, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, own); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := checkPreUpLink(own, target); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(hooks, "netos-l2tp-srv31")
	if err := os.Symlink(filepath.Join(state, "somebody-else"), foreign); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(hooks, "netos-l2tp-srv32")
	if err := os.WriteFile(file, []byte("foreign"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{foreign, file} {
		if err := checkPreUpLink(p, target); err == nil {
			t.Fatalf("foreign hook accepted: %s", p)
		}
	}
	if err := RemoveL2TPPreUpHooks(state, hooks); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(own); !os.IsNotExist(err) {
		t.Fatalf("own dangling hook remains: %v", err)
	}
	for _, p := range []string{foreign, file} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("foreign hook removed: %v", err)
		}
	}
}

func TestL2TPHookRunsThroughDebianRunParts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Debian run-parts")
	}
	server := config.VPNServer{Index: 30, ID: "l2tp", Subnet: "10.99.1.1/24", Enabled: true}
	cfg := &config.Config{}
	cfg.Samba.Enabled = true
	cfg.Samba.VPNs = []string{server.ID}
	dir, hooks := t.TempDir(), t.TempDir()
	target := filepath.Join(dir, "vpn-l2tp-srv30.pre-up")
	log := filepath.Join(dir, "calls")
	files := map[string]string{
		target:                          string(renderL2TPPreUp(server, cfg)),
		filepath.Join(dir, "systemctl"): "#!/bin/sh\nexit 0\n",
		filepath.Join(dir, "ss"):        "#!/bin/sh\necho checked >> \"$CALLS\"\necho 'LISTEN 0 50 10.99.1.1:445 0.0.0.0:*'\n",
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, filepath.Join(hooks, "netos-l2tp-srv30")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("run-parts", hooks, "--arg=ppp-srv30", "--arg=tty", "--arg=0", "--arg=10.99.1.1", "--arg=10.99.1.2", "--arg=")
	cmd.Env = append(os.Environ(), "PATH="+dir+":/usr/bin:/bin", "CALLS="+log)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run-parts: %v %s", err, out)
	}
	if data, err := os.ReadFile(log); err != nil || strings.TrimSpace(string(data)) != "checked" {
		t.Fatalf("hook not dispatched: %v %s", err, data)
	}
	ppp := renderL2TPPPP(server, config.L2TPServerConfig{})
	if strings.Contains(ppp, "ip-pre-up-script") {
		t.Fatal("pppd 2.4.9 cannot parse ip-pre-up-script")
	}
}

package vpnservers

import (
	"github.com/netos-router/netos/internal/config"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestL2TPMultiuserRendering(t *testing.T) {
	s := config.VPNServer{Index: 9999, Enabled: true, Subnet: "10.99.0.1/24", Peers: []config.VPNPeer{
		{Enabled: true, Address: "10.99.0.2", Credentials: map[string]string{"username": "alice", "password": "alice-secret"}},
		{Enabled: true, Address: "10.99.0.3", Credentials: map[string]string{"username": "bob", "password": "bob-secret"}},
		{Enabled: false, Address: "10.99.0.4", Credentials: map[string]string{"username": "disabled", "password": "disabled-secret"}},
	}}
	chap := l2tpChapBlock(s)
	if !strings.Contains(chap, `"alice" "netos-l2tp-srv9999" "alice-secret" 10.99.0.2`) || !strings.Contains(chap, `"bob" "netos-l2tp-srv9999" "bob-secret" 10.99.0.3`) || strings.Contains(chap, "disabled-secret") {
		t.Fatalf("wrong per-user credentials: %s", chap)
	}
	conf := renderL2TPConf(s, config.L2TPServerConfig{Listen: "10.0.0.1"}, "test.ppp")
	if !strings.Contains(conf, "assign ip = no") || strings.Contains(conf, "ip range") || strings.Contains(renderL2TPPPP(s, config.L2TPServerConfig{}), "ifname") {
		t.Fatal("global address or interface assignment remains")
	}
}

func TestL2TPPreUpBindsAuthenticatedPeerAndRejectsCollisions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executes Linux hook")
	}
	// Shell metacharacters in an allowed username must remain literal.
	username := "a'$(touch injected)*"
	s := config.VPNServer{Index: 9, Enabled: true, Subnet: "10.99.0.1/24", Peers: []config.VPNPeer{{Enabled: true, Address: "10.99.0.2", Credentials: map[string]string{"username": username}}}}
	for _, tc := range []struct {
		name, user, address string
		collision, fail     bool
	}{
		{"own", username, "10.99.0.2", false, false},
		{"foreign address", username, "10.99.0.3", false, true},
		{"foreign login", "other", "10.99.0.2", false, true},
		{"duplicate", username, "10.99.0.2", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			hook := filepath.Join(dir, "hook")
			if err := os.WriteFile(hook, renderL2TPPreUp(s, &config.Config{}), 0700); err != nil {
				t.Fatal(err)
			}
			fake := "#!/bin/sh\necho \"$*\" >> \"$DIR/calls\"\n[ \"$2\" != set ] || [ \"$COLLISION\" != yes ]\n"
			if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/sh", hook, "ppp7", "tty", "0", "10.99.0.1", tc.address)
			collision := "no"
			if tc.collision {
				collision = "yes"
			}
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+":/usr/bin:/bin", "DIR="+dir, "PEERNAME="+tc.user, "COLLISION="+collision)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("err=%v output=%s", err, out)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
			if strings.Contains(string(calls), "link delete dev ppp7") != tc.fail {
				t.Fatalf("wrong rejection: %s", calls)
			}
			if !tc.fail && string(calls) != "link set dev ppp7 name pp9-0a630002\n" {
				t.Fatalf("wrong mapping: %s", calls)
			}
			if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
				t.Fatal("username executed as shell")
			}
		})
	}
}

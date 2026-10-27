//go:build linux

package vpnservers

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIntegrationL2TPIPsecGuard(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	const ns = "netos-l2tp-guard"
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
		return string(out)
	}
	run("ip", "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", ns).Run() })
	run("ip", "-n", ns, "link", "set", "lo", "up")
	run("ip", "netns", "exec", ns, "iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
	server := config.VPNServer{Type: "l2tp", Index: 1, Config: map[string]any{"listen": "0.0.0.0", "ipsec": true}}
	script := filepath.Join(t.TempDir(), "guard")
	if err := os.WriteFile(script, renderL2TPIPsecGuard(server), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		run("ip", "netns", "exec", ns, "/bin/sh", script)
	}
	saved := run("ip", "netns", "exec", ns, "iptables-save", "-t", "mangle")
	if strings.Count(saved, "-j "+L2TPIPsecGuardChain) != 1 || !strings.Contains(saved, "--dport 80 -j ACCEPT") {
		t.Fatalf("duplicate guard or lost unrelated rule: %s", saved)
	}
	// Both sockets are local and the ordinary filter policy is ACCEPT. Only
	// unprotected L2TP must be rejected before any service can consume it.
	run("ip", "netns", "exec", ns, "python3", "-c", `import socket
for port in (1701,1702):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',port));s.settimeout(0.3)
 c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'probe',('127.0.0.1',port))
 try: data=s.recv(32);received=True
 except socket.timeout: received=False
 assert received==(port==1702),(port,received)
 s.close();c.close()
print('plaintext1701 blocked, unrelated1702 accepted')`)
	t.Log(run("ip", "netns", "exec", ns, "iptables", "-t", "mangle", "-nvL", L2TPIPsecGuardChain))
}

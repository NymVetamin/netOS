//go:build linux

package channels

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

type awgFaultRunner struct {
	system.Runner
	fail         bool
	failDelete   bool
	afterFailure bool
}

func (r *awgFaultRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if r.fail && name == "ip" && strings.HasPrefix(strings.Join(args, " "), "link set dev wg-ch1 mtu ") {
		r.fail = false
		r.afterFailure = true
		return "", errors.New("injected MTU failure after native syncconf")
	}
	if r.failDelete && r.afterFailure && name == "ip" && strings.Join(args, " ") == "link delete wg-ch1" {
		r.failDelete = false
		return "", errors.New("injected rollback delete failure")
	}
	return r.Runner.Run(ctx, name, args...)
}

// Run only in a disposable Linux VM with the official AWG module installed:
// unshare --mount --net env NETOS_AWG_INTEGRATION=1 ./channels.test -test.run '^TestIntegrationAmneziaWGRollback$' -test.v
func TestIntegrationAmneziaWGRollback(t *testing.T) {
	if os.Getenv("NETOS_AWG_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("explicit isolated root AWG integration only")
	}
	for _, command := range []string{"ip", "awg", "ping", "conntrack", "mount"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("integration prerequisite %s: %v", command, err)
		}
	}
	for _, kind := range []string{"net", "mnt"} {
		self, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		host, err := os.Readlink("/proc/1/ns/" + kind)
		if err != nil || self == host {
			t.Fatal("refusing host namespace", kind, err)
		}
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	run("ip", "link", "set", "lo", "up")
	ns := fmt.Sprintf("netos-awg-rollback-%d", os.Getpid())
	run("ip", "netns", "add", ns)
	defer exec.Command("ip", "netns", "del", ns).Run()
	remote := func(name string, args ...string) string {
		t.Helper()
		return run("ip", append([]string{"netns", "exec", ns, name}, args...)...)
	}
	run("ip", "link", "add", "underlay", "type", "veth", "peer", "name", "remote")
	run("ip", "link", "set", "remote", "netns", ns)
	run("ip", "addr", "add", "192.0.2.1/30", "dev", "underlay")
	run("ip", "link", "set", "underlay", "up")
	remote("ip", "link", "set", "lo", "up")
	remote("ip", "addr", "add", "192.0.2.2/30", "dev", "remote")
	remote("ip", "link", "set", "remote", "up")
	key := func() (string, string) {
		private := run("awg", "genkey")
		cmd := exec.Command("awg", "pubkey")
		cmd.Stdin = strings.NewReader(private)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return private, strings.TrimSpace(string(out))
	}
	priv, pub := key()
	remotePriv, remotePub := key()
	root := t.TempDir()
	peerConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = 51821\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 25\nH1 = 100\nH2 = 200\nH3 = 300\nH4 = 400\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.44.0.2/32\n", remotePriv, pub)
	peerPath := filepath.Join(root, "peer.conf")
	if err := os.WriteFile(peerPath, []byte(peerConf), 0600); err != nil {
		t.Fatal(err)
	}
	remote("ip", "link", "add", "awg-peer", "type", "amneziawg")
	remote("awg", "setconf", "awg-peer", peerPath)
	remote("ip", "addr", "add", "10.44.0.1/24", "dev", "awg-peer")
	remote("ip", "link", "set", "awg-peer", "up")
	old := awgChannelConfig().Channels[1]
	old.Config["address"], old.Config["endpoint"] = "10.44.0.2/24", "192.0.2.2:51821"
	old.Config["private_key"], old.Config["peer_public_key"] = priv, remotePub
	old.Config["allowed_ips"] = []string{"10.44.0.0/24"}
	params := old.Config["amneziawg"].(map[string]any)
	delete(params, "i1")
	params["h1"], params["h2"], params["h3"], params["h4"] = "100", "200", "300", "400"
	r := &awgFaultRunner{Runner: system.NewExec()}
	s := New(r, filepath.Join(root, "channels"))
	if err := os.MkdirAll(s.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	s.AppArmorDir, s.AppArmorProfiles = filepath.Join(root, "apparmor"), filepath.Join(root, "no-profiles")
	ctx := context.Background()
	if _, err := s.applyWireGuard(ctx, old, false, true); err != nil {
		t.Fatal(err)
	}
	ping := func() { t.Helper(); run("ping", "-n", "-c", "2", "-W", "5", "-I", "wg-ch1", "10.44.0.1") }
	ping()
	params["i1"] = "<b 0xc0ffee>"
	r.fail = true
	if _, err := s.applyWireGuard(ctx, old, true, true); err == nil || !strings.Contains(err.Error(), "injected MTU failure") {
		t.Fatalf("missing injected failure: %v", err)
	}
	assertCleared := func() {
		t.Helper()
		out := run("awg", "showconf", "wg-ch1")
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "I1") && strings.Contains(line, "c0ffee") {
				t.Fatal("rollback retained new I1 in kernel")
			}
		}
		ping()
	}
	assertCleared()
	delete(params, "i1")
	if _, err := s.applyWireGuard(ctx, old, true, true); err != nil {
		t.Fatal(err)
	}
	assertCleared()
	indexBefore := run("cat", "/sys/class/net/wg-ch1/ifindex")
	if _, err := s.applyWireGuard(ctx, old, true, true); err != nil {
		t.Fatal(err)
	}
	if indexAfter := run("cat", "/sys/class/net/wg-ch1/ifindex"); indexAfter != indexBefore {
		t.Fatal("unchanged settings recreated link")
	}
	params["i1"] = "<b 0xc0ffee>"
	if _, err := s.applyWireGuard(ctx, old, true, true); err != nil {
		t.Fatal(err)
	}
	if out := run("awg", "showconf", "wg-ch1"); !strings.Contains(out, "c0ffee") {
		t.Fatal("retry did not apply I1")
	}
	ping()
	params["i1"] = "<b 0xcafe>"
	r.fail, r.failDelete, r.afterFailure = true, true, false
	if _, err := s.applyWireGuard(ctx, old, true, true); err == nil || !strings.Contains(err.Error(), "injected rollback delete failure") {
		t.Fatalf("missing rollback delete failure: %v", err)
	}
	params["i1"] = "<b 0xc0ffee>"
	if _, err := s.applyWireGuard(ctx, old, true, true); err != nil {
		t.Fatal(err)
	}
	if out := run("awg", "showconf", "wg-ch1"); !strings.Contains(out, "c0ffee") || strings.Contains(out, "cafe") {
		t.Fatal("retry after rollback failure retained wrong I1")
	}
	ping()
	t.Log("native kernel rollback, readback, traffic and old/new retries PASS")
}

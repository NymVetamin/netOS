//go:build linux

package channels_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/amneziawg"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
)

// A copy of the test executable runs the same multicall handler as netosd.
func TestAmneziaWGDaemonProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--" {
			if err := amneziawg.Execute(context.Background(), os.Args[i+1:], os.Stdout); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Skip("child helper")
}

func TestIntegrationAmneziaWGApply(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated root integration")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, _ := os.Readlink("/proc/self/ns/" + kind)
		host, _ := os.Readlink("/proc/1/ns/" + kind)
		if self == host {
			t.Fatal("refusing host namespace")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	run("ip", "link", "set", "lo", "up")
	root, err := os.MkdirTemp("/var/lib", "netos-awg-ci-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	binary := filepath.Join(root, "runner")
	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(binary, data, 0700); err != nil {
		t.Fatal(err)
	}
	ns := fmt.Sprintf("netos-awg-peer-%d", os.Getpid())
	run("ip", "netns", "add", ns)
	defer exec.Command("ip", "netns", "del", ns).Run()
	remote := func(name string, args ...string) string {
		t.Helper()
		return run("ip", append([]string{"netns", "exec", ns, name}, args...)...)
	}
	run("ip", "link", "add", "awgtransport", "type", "veth", "peer", "name", "awgremote")
	run("ip", "link", "set", "awgremote", "netns", ns)
	run("ip", "addr", "add", "192.0.2.1/30", "dev", "awgtransport")
	run("ip", "link", "set", "awgtransport", "up")
	remote("ip", "addr", "add", "192.0.2.2/30", "dev", "awgremote")
	remote("ip", "link", "set", "awgremote", "up")
	remote("ip", "link", "set", "lo", "up")
	peer := exec.CommandContext(ctx, "ip", "netns", "exec", ns, binary, "-test.run=TestAmneziaWGDaemonProcess", "--", "serve", "awg-ch992")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		peer.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- peer.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			peer.Process.Kill()
			<-done
		}
	}()
	wait := func(f func() bool) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if f() {
				return
			}
			if ctx.Err() != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("runtime did not recover")
	}
	wait(func() bool {
		var out strings.Builder
		return amneziawg.Execute(ctx, []string{"show", "awg-ch992"}, &out) == nil
	})
	key := func() (string, string) {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	}
	opts := config.AmneziaWGOptions{Jc: 3, Jmin: 30, Jmax: 50, S1: 16, S2: 17, H1: "101", H2: "102", H3: "103", H4: "104"}
	r := system.NewExec()
	for _, role := range []string{"client", "server"} {
		func() {
			t.Log("role:", role)
			// Separate scenarios must not reuse the previous role's session keys.
			// Updating an endpoint preserves a live peer's handshake by design.
			localKey, localPub := key()
			peerKey, peerPub := key()
			name := "awg-ch991"
			if role == "server" {
				name = "awg-srv991"
			}
			unitName := system.AmneziaWGUnitName(name)
			unitPath := filepath.Join("/etc/systemd/system", unitName)
			if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
				t.Fatal("test unit already exists")
			}
			confPath := filepath.Join(root, role, name+".conf")
			table := 0
			if role == "client" {
				table = 1991
			}
			unit, err := system.RenderAmneziaWGUnit(name, confPath, "10.252.0.1/24", 1420, table, true)
			if err != nil {
				t.Fatal(err)
			}
			// Only execution location changes; the generated unit remains intact for Health.
			var post strings.Builder
			for _, line := range strings.Split(string(unit), "\n") {
				if strings.HasPrefix(line, "ExecStartPost=") {
					post.WriteString(strings.ReplaceAll(line, "/usr/local/bin/netosd amneziawg", binary+" -test.run=TestAmneziaWGDaemonProcess --") + "\n")
				}
			}
			dropin := unitPath + ".d"
			if _, err := os.Stat(dropin); !os.IsNotExist(err) {
				t.Fatal("test drop-in exists")
			}
			if err := os.Mkdir(dropin, 0755); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf("[Service]\nNetworkNamespacePath=/proc/%d/ns/net\nExecStart=\nExecStart=%s -test.run=TestAmneziaWGDaemonProcess -- serve %s\nExecStartPost=\n%s", os.Getpid(), binary, name, post.String())
			if err := os.WriteFile(filepath.Join(dropin, "ci.conf"), []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
			defer func() {
				exec.Command("systemctl", "disable", "--now", unitName).Run()
				os.Remove(unitPath)
				os.RemoveAll(dropin)
				exec.Command("systemctl", "daemon-reload").Run()
				exec.Command("systemctl", "reset-failed", unitName).Run()
			}()
			c := config.Default()
			c.Components = []config.Component{{ID: "amneziawg", Installed: true}}
			c.Channels = nil
			var apply func(*config.Config) error
			var health func(*config.Config) error
			if role == "client" {
				c.Channels = []config.Channel{{ID: "awg", Index: 991, Name: "AWG test", Enabled: true, Type: "amneziawg", Mode: "tun", Config: map[string]any{"private_key": localKey, "peer_public_key": peerPub, "endpoint": "192.0.2.2:51992", "address": "10.252.0.1/24", "allowed_ips": []string{"0.0.0.0/0"}, "persistent_keepalive": 1, "amnezia": opts}}}
				s := channels.New(r, filepath.Join(root, role))
				s.RTTablesPath = filepath.Join(root, "rt_tables")
				apply = func(c *config.Config) error { return s.Apply(ctx, c) }
				health = func(c *config.Config) error { return s.Health(ctx, c) }
			} else {
				c.VPNServers = []config.VPNServer{{ID: "awg", Index: 991, Name: "AWG test", Enabled: true, Type: "amneziawg", Port: 51991, Subnet: "10.252.0.1/24", Config: map[string]any{"private_key": localKey, "amnezia": opts}, Peers: []config.VPNPeer{{ID: "peer", Enabled: true, Address: "10.252.0.2", Credentials: map[string]string{"public_key": peerPub}}}}}
				s := vpnservers.New(r, filepath.Join(root, role))
				apply = func(c *config.Config) error { return s.Apply(ctx, c) }
				health = func(c *config.Config) error { return s.Health(ctx, c) }
			}
			if err := apply(c); err != nil {
				t.Fatal(err)
			}
			if err := health(c); err != nil {
				t.Fatal(err)
			}
			var port strings.Builder
			if err := amneziawg.Execute(ctx, []string{"show", name, "listen-port"}, &port); err != nil {
				t.Fatal(err)
			}
			peerConf := "[Interface]\nPrivateKey = " + peerKey + "\nListenPort = 51992\n" + opts.NativeParameters() + "[Peer]\nPublicKey = " + localPub + "\nEndpoint = 192.0.2.1:" + strings.TrimSpace(port.String()) + "\nAllowedIPs = 10.252.0.1/32\nPersistentKeepalive = 1\n"
			peerPath := filepath.Join(root, "peer.conf")
			if err := os.WriteFile(peerPath, []byte(peerConf), 0600); err != nil {
				t.Fatal(err)
			}
			if err := amneziawg.Execute(ctx, []string{"syncconf", "awg-ch992", peerPath}, &strings.Builder{}); err != nil {
				t.Fatal(err)
			}
			remote("ip", "addr", "replace", "10.252.0.2/24", "dev", "awg-ch992")
			remote("ip", "link", "set", "awg-ch992", "up")
			// A server learns its peer endpoint from the client's first handshake.
			if role == "server" {
				remote("ping", "-c", "2", "-W", "2", "10.252.0.1")
				run("ping", "-c", "2", "-W", "2", "10.252.0.2")
			} else {
				run("ping", "-c", "2", "-W", "2", "10.252.0.2")
				remote("ping", "-c", "2", "-W", "2", "10.252.0.1")
			}
			pid := run("systemctl", "show", unitName, "-p", "MainPID", "--value")
			t.Log(role, "initial bidirectional traffic passed")
			if err := apply(c); err != nil {
				t.Fatal(err)
			}
			if again := run("systemctl", "show", unitName, "-p", "MainPID", "--value"); again != pid {
				t.Fatal("unchanged apply restarted tunnel")
			}
			run("systemctl", "kill", "--signal=SIGKILL", "--kill-whom=main", unitName)
			wait(func() bool { return health(c) == nil })
			// Client source ports can change on restart; send first from the client.
			if role == "client" {
				run("ping", "-c", "2", "-W", "2", "10.252.0.2")
			} else {
				// The surviving client retains its session. Upstream starts a new
				// handshake after 10s KeepaliveTimeout + 5s RekeyTimeout + jitter
				// when data receives no response. Keep sending data through this
				// bounded recovery window; do not reset the peer to hide recovery.
				started := time.Now()
				deadline := started.Add(25 * time.Second)
				for {
					err := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", "10.252.0.1").Run()
					if err == nil {
						t.Logf("server restart traffic recovered after %s", time.Since(started))
						break
					}
					if ctx.Err() != nil || time.Now().After(deadline) {
						var state strings.Builder
						amneziawg.Execute(ctx, []string{"show", name, "telemetry"}, &state)
						t.Fatalf("server restart did not restore traffic: %v; public telemetry: %s", err, state.String())
					}
				}
				remote("ping", "-c", "2", "-W", "2", "10.252.0.1")
				run("ping", "-c", "2", "-W", "2", "10.252.0.2")
			}
			empty := config.Default()
			empty.Channels = nil
			if err := apply(empty); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join("/sys/class/net", name)); !os.IsNotExist(err) {
				t.Fatal("removed interface retained")
			}
			if _, err := os.Stat(confPath); !os.IsNotExist(err) {
				t.Fatal("removed config retained")
			}
			if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
				t.Fatal("removed unit retained")
			}
			if err := apply(c); err != nil {
				t.Fatal(err)
			}
			if err := health(c); err != nil {
				t.Fatal(err)
			}
			if err := apply(empty); err != nil {
				t.Fatal(err)
			}
		}()
	}
}

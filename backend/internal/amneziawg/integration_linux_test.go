//go:build linux

package amneziawg

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

	"github.com/netos-router/netos/internal/config"
)

func TestAmneziaWGProcess(t *testing.T) {
	name := os.Getenv("NETOS_AWG_CHILD")
	if name == "" {
		t.Skip("child helper")
	}
	if !validInterface(name) {
		t.Fatal("invalid test interface")
	}
	if err := serve(context.Background(), name); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationAmneziaWG(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("root isolated namespace required")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == host {
		t.Fatal("refusing host namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = os.Remove(SocketDir) })
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %s %v", name, args, out, err)
		}
		return string(out)
	}
	ns := fmt.Sprintf("awg-test-%d", os.Getpid())
	run("ip", "netns", "add", ns)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	run("ip", "link", "add", "awglink", "type", "veth", "peer", "name", "awgpeer")
	run("ip", "link", "set", "awgpeer", "netns", ns)
	run("ip", "addr", "add", "192.0.2.1/30", "dev", "awglink")
	run("ip", "link", "set", "awglink", "up")
	run("ip", "link", "set", "lo", "up")
	run("ip", "netns", "exec", ns, "ip", "addr", "add", "192.0.2.2/30", "dev", "awgpeer")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "awgpeer", "up")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	start := func(name string, remote bool) {
		t.Helper()
		args := []string{os.Args[0], "-test.run=^TestAmneziaWGProcess$"}
		if remote {
			args = append([]string{"ip", "netns", "exec", ns}, args...)
		}
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "NETOS_AWG_CHILD="+name)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cmd.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				cmd.Process.Kill()
				<-done
			}
		})
		for i := 0; i < 100; i++ {
			if _, err := exchange(ctx, filepath.Join(SocketDir, name+".sock"), "get=1\n\n"); err == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("AmneziaWG startup timeout")
	}
	start("awg-ch999", false)
	start("awg-srv999", true)
	key := func() (string, string) {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	}
	clientKey, clientPub := key()
	serverKey, serverPub := key()
	protection, _ := key()
	options := config.AmneziaWGOptions{Jc: 4, Jmin: 30, Jmax: 50, S1: 16, S2: 17, S3: 18, S4: 19, H1: "100-200", H2: "300-400", H3: "500-600", H4: "700-800", HeaderProtectionKey: protection, ContentPaddingAddition: "0-16", I1: "<b 0x12345678><r 8><t>"}
	makeConfig := func(private, public, endpoint, subnet string) string {
		return "[Interface]\nPrivateKey = " + private + "\nListenPort = 51999\n" + options.NativeParameters() + "[Peer]\nPublicKey = " + public + "\nEndpoint = " + endpoint + "\nAllowedIPs = " + subnet + "\nPersistentKeepalive = 1\n"
	}
	sync := func(name, text string) State {
		t.Helper()
		want, err := ParseNative(ctx, text)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(SocketDir, name+".sock")
		live, err := exchange(ctx, path, "get=1\n\n")
		if err != nil {
			t.Fatal(err)
		}
		if delta := Delta(want, live); delta != "" {
			if _, err := exchange(ctx, path, "set=1\n"+delta+"\n"); err != nil {
				t.Fatal(err)
			}
		}
		return want
	}
	clientText := makeConfig(clientKey, serverPub, "192.0.2.2:51999", "10.251.0.2/32")
	serverText := makeConfig(serverKey, clientPub, "192.0.2.1:51999", "10.251.0.1/32")
	sync("awg-ch999", clientText)
	sync("awg-srv999", serverText)
	run("ip", "addr", "add", "10.251.0.1/24", "dev", "awg-ch999")
	run("ip", "link", "set", "awg-ch999", "up")
	run("ip", "netns", "exec", ns, "ip", "addr", "add", "10.251.0.2/24", "dev", "awg-srv999")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "awg-srv999", "up")
	run("ping", "-c", "3", "-W", "3", "10.251.0.2")
	for _, tc := range []struct{ name, text string }{{"awg-ch999", clientText}, {"awg-srv999", serverText}} {
		want, err := ParseNative(ctx, tc.text)
		if err != nil {
			t.Fatal(err)
		}
		live, err := exchange(ctx, filepath.Join(SocketDir, tc.name+".sock"), "get=1\n\n")
		if err != nil {
			t.Fatal(err)
		}
		if delta := Delta(want, live); delta != "" {
			t.Fatalf("unchanged configuration would modify %s (field names only): %v", tc.name, deltaFieldNames(delta))
		}
		if len(live.Peers) != 1 || live.Peers[0].Values["last_handshake_time_sec"] == "0" || live.Peers[0].Values["rx_bytes"] == "0" {
			t.Fatal("handshake or transfer not confirmed")
		}
		sync(tc.name, tc.text)
	}
	run("ip", "netns", "exec", ns, "ping", "-c", "2", "-W", "3", "10.251.0.1")
	// Removing a peer must actually prevent further traffic; restoring it
	// must recover without recreating either interface.
	sync("awg-srv999", strings.Split(serverText, "[Peer]")[0])
	if out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", "10.251.0.2").CombinedOutput(); err == nil {
		t.Fatalf("removed peer still passes traffic: %s", out)
	}
	sync("awg-srv999", serverText)
	run("ping", "-c", "3", "-W", "3", "10.251.0.2")
}

func deltaFieldNames(delta string) []string {
	var keys []string
	for _, line := range strings.Split(delta, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if ok {
			keys = append(keys, key)
		}
	}
	return keys
}

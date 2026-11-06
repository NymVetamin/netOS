package vpnservers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"golang.org/x/net/proxy"
)

// Runs the rendered policy through a real Xray binary on loopback, on any OS.
// Only the stats listener is removed: its fixed production /run path is not
// available to an unprivileged test, and it does not participate in routing.
func TestPolicyBlockRealXray(t *testing.T) {
	binary := os.Getenv("NETOS_XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NETOS_XRAY_TEST_BINARY to test real Xray")
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	selected := []byte("GET / HTTP/1.1\r\nHost: selected.test\r\n\r\n")
	http := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	for _, mode := range []string{"block", "route", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			reservation, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()
			cfg, server := xrayServerConfig()
			cfg.DNS.Enabled = false
			server.Port = port
			server.DefaultChannel = "direct"
			server.Config = map[string]any{"protocol": "socks", "listen": "127.0.0.1"}
			server.Peers = []config.VPNPeer{{ID: "phone", Enabled: true, Address: "10.10.0.2", Credentials: map[string]string{"username": "test", "password": "local-test"}}}
			_, targetPort, _ := net.SplitHostPort(target.Addr().String())
			cfg.Policies = []config.Policy{{ID: "selected", Enabled: mode != "disabled", VPNServer: server.ID, Protocol: "tcp", DstIP: "127.0.0.1", DstPort: targetPort, Channel: config.InternetBlockChannel}}
			if mode == "route" {
				cfg.Policies[0].Channel = "direct"
			}
			raw, e := RenderXray(server, cfg)
			if e != nil {
				t.Fatal(e)
			}
			var doc map[string]any
			json.Unmarshal(raw, &doc)
			delete(doc, "api")
			raw, _ = json.Marshal(doc)
			path := filepath.Join(t.TempDir(), "config.json")
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(binary, "run", "-config", path)
			var logs bytes.Buffer
			cmd.Stdout = &logs
			cmd.Stderr = &logs
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				cmd.Process.Kill()
				cmd.Wait()
				if t.Failed() {
					t.Log(logs.String())
				}
			}()
			address := fmt.Sprintf("127.0.0.1:%d", port)
			ready := false
			for i := 0; i < 100; i++ {
				c, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
				if e == nil {
					c.Close()
					ready = true
					break
				}
				time.Sleep(30 * time.Millisecond)
			}
			if !ready {
				t.Fatal("Xray listener unavailable")
			}
			dialer, e := proxy.SOCKS5("tcp", address, &proxy.Auth{User: "test", Password: "local-test"}, &net.Dialer{Timeout: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			for _, payload := range [][]byte{http, selected, selected, http} {
				c, e := dialer.Dial("tcp", target.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				c.SetDeadline(time.Now().Add(2 * time.Second))
				_, e = c.Write(payload)
				buf := make([]byte, len(payload))
				if e == nil {
					_, e = io.ReadFull(c, buf)
				}
				c.Close()
				blocked := mode == "block"
				if blocked && e == nil {
					t.Fatal("selected destination escaped block")
				}
				if !blocked && (e != nil || !bytes.Equal(buf, payload)) {
					t.Fatalf("ordinary/allowed traffic failed: %v", e)
				}
			}
		})
	}
}

package api

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/tlsutil"
	"golang.org/x/net/proxy"
)

// Runs only on an explicitly authorized machine with Xray already installed.
// All listeners and traffic stay on loopback; installed services are untouched.
func TestXrayProfilesRealConnections(t *testing.T) {
	bin := os.Getenv("NETOS_TEST_XRAY")
	if bin == "" {
		t.Skip("set NETOS_TEST_XRAY for real Xray connections")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "netos-profile-roundtrip") }))
	defer target.Close()
	camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "camouflage") }))
	camouflage.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	camouflage.EnableHTTP2 = true
	camouflage.StartTLS()
	defer camouflage.Close()
	port := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	start := func(t *testing.T, doc map[string]any, dir, name string) func() {
		t.Helper()
		data, _ := json.Marshal(doc)
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "run", "-test", "-config", path).CombinedOutput(); err != nil {
			t.Fatalf("%s validation: %v %s", name, err, out)
		}
		log, err := os.Create(filepath.Join(dir, name+".log"))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "run", "-config", path)
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		return func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = log.Close() }
	}
	for _, testMode := range []string{"normal", "internet-block"} {
		for _, protocol := range []string{"reality", "vless", "trojan", "hysteria", "vmess", "shadowsocks", "socks", "http"} {
			t.Run(testMode+"/"+protocol, func(t *testing.T) {
				dir := t.TempDir()
				cfg := config.Default()
				s := profileTestServer(protocol)
				if testMode == "internet-block" {
					s.Peers[0].Channel = config.InternetBlockChannel
					cfg.Networks = []config.Network{{ID: "internal", Enabled: true, RouterAddress: "127.0.0.1/32"}}
				}
				// HTTP Basic separates username/password at the first colon.
				s.Peers[0].Credentials["username"] = "test-user"
				s.Port = port()
				s.Config["public_endpoint"] = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port))
				s.Config["listen"] = "127.0.0.1"
				if protocol == "reality" {
					s.Config["destination"] = camouflage.Listener.Addr().String()
				}
				cert, key, _, err := tlsutil.EnsureSelfSignedForNames(dir, "router", "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				certPEM, _ := os.ReadFile(cert)
				keyPEM, _ := os.ReadFile(key)
				s.Config["tls"] = map[string]any{"mode": "custom", "cert_pem": string(certPEM), "private_key": string(keyPEM)}
				body, err := vpnservers.RenderXray(s, cfg)
				if err != nil {
					t.Fatal(err)
				}
				var server map[string]any
				if err := json.Unmarshal(body, &server); err != nil {
					t.Fatal(err)
				}
				server["api"].(map[string]any)["listen"] = filepath.Join(dir, "stats.sock")
				in := server["inbounds"].([]any)[0].(map[string]any)
				in["listen"] = "127.0.0.1"
				if stream, ok := in["streamSettings"].(map[string]any); ok {
					if tls, ok := stream["tlsSettings"].(map[string]any); ok {
						tls["certificates"] = []any{map[string]any{"certificateFile": cert, "keyFile": key}}
					}
				}
				stopServer := start(t, server, dir, "server")
				defer stopServer()
				pin, err := xrayProfilePin(cfg, s)
				if err != nil {
					t.Fatal(err)
				}
				p, err := xrayClientProfile(s, s.Peers[0], pin)
				if err != nil {
					t.Fatal(err)
				}
				clientPort := port()
				p.Config["inbounds"].([]any)[0].(map[string]any)["port"] = clientPort
				stopClient := start(t, p.Config, dir, "client")
				defer stopClient()
				dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), nil, &net.Dialer{Timeout: 3 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				transport := &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				var last error
				for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
					resp, err := client.Get(target.URL)
					if err == nil {
						data, readErr := io.ReadAll(resp.Body)
						resp.Body.Close()
						if readErr == nil && string(data) == "netos-profile-roundtrip" {
							if testMode == "internet-block" {
								external := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "must-not-pass") }))
								external.Listener.Close()
								l, e := net.Listen("tcp4", "127.0.0.2:0")
								if e != nil {
									t.Fatal(e)
								}
								external.Listener = l
								external.Start()
								defer external.Close()
								resp, e := client.Get(external.URL)
								if e == nil {
									resp.Body.Close()
									t.Fatal("internet-only block allowed non-internal target")
								}
							}
							return
						}
						err = fmt.Errorf("unexpected response: %v", readErr)
					}
					last = err
					time.Sleep(100 * time.Millisecond)
				}
				for _, name := range []string{"server", "client"} {
					data, _ := os.ReadFile(filepath.Join(dir, name+".log"))
					t.Logf("%s: %s", name, data)
				}
				t.Fatalf("traffic failed: %v", last)
			})
		}
	}
}

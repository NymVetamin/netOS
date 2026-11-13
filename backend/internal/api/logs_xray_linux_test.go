//go:build linux

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
	"github.com/netos-router/netos/internal/tlsutil"
	"golang.org/x/net/proxy"
)

func TestIntegrationXrayAccessJournal(t *testing.T) {
	testXrayAccessJournal(t, true, false, "socks")
}

func TestIntegrationXraySanitizedJournal(t *testing.T) {
	if os.Getenv("NETOS_XRAY_LOG_NETOS") == "" {
		t.Skip("requires current netos binary")
	}
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) { testXrayAccessJournal(t, enabled, true, "socks") })
	}
	t.Run("vless", func(t *testing.T) { testXrayAccessJournal(t, false, true, "vless") })
}

func testXrayAccessJournal(t *testing.T, monitor, worker bool, protocol string) {
	binary := os.Getenv("NETOS_XRAY_LOG_BINARY")
	if binary == "" {
		t.Skip("requires authorized Linux and Xray binary")
	}
	ctx := context.Background()
	run := &system.Exec{Timeout: 10 * time.Second, MaxOutputBytes: 4 << 20}
	const unit = "netos-xray-srv993.service"
	state, err := run.Run(ctx, "systemctl", "show", unit, "--property=LoadState", "--value")
	if err != nil || strings.TrimSpace(state) != "not-found" {
		t.Fatal("test unit occupied", state, err)
	}
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); io.Copy(c, c) }()
		}
	}()
	server := config.VPNServer{ID: "log-probe", Index: 993, Type: "xray", Enabled: true, Port: port, DefaultChannel: "direct", Config: map[string]any{"protocol": "socks"}, Peers: []config.VPNPeer{{ID: "peer", Enabled: true, Credentials: map[string]string{"username": "log-user", "password": "log-password"}}}}
	server.Config["protocol"] = protocol
	server.Peers[0].Credentials["uuid"] = "11111111-1111-1111-1111-111111111111"
	cfg := config.Default()
	cfg.TrafficMonitor.Enabled = monitor
	raw, err := vpnservers.RenderXray(server, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// Keep this generated-config test isolated from public interfaces and /run.
	doc["inbounds"].([]any)[0].(map[string]any)["listen"] = "127.0.0.1"
	doc["api"].(map[string]any)["listen"] = filepath.Join(root, "stats.sock")
	var clientTLS *tls.Config
	if protocol == "vless" {
		cert, key, _, err := tlsutil.EnsureSelfSignedForNames(root, "localhost", "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		pem, err := os.ReadFile(cert)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatal("invalid test certificate")
		}
		clientTLS = &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
		in := doc["inbounds"].([]any)[0].(map[string]any)
		settings := in["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
		settings["certificates"] = []any{map[string]any{"certificateFile": cert, "keyFile": key}}
	}
	raw, _ = json.Marshal(doc)
	path := filepath.Join(root, "xray.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run.Run(ctx, "systemctl", "stop", unit); run.Run(ctx, "systemctl", "reset-failed", unit) })
	from := time.Now().UTC()
	args := []string{"--unit=" + unit, "--collect", "--property=StandardOutput=journal", "--property=StandardError=journal"}
	if worker {
		// Private mounts provide the real command paths without installing either
		// executable or replacing files belonging to the host.
		args = append(args, "--property=TemporaryFileSystem=/usr/local/bin:ro",
			"--property=BindReadOnlyPaths="+binary+":/usr/local/bin/xray "+os.Getenv("NETOS_XRAY_LOG_NETOS")+":/usr/local/bin/netos",
			"--property=SyslogIdentifier=netos-xray",
			"--property=ExecStartPre="+os.Getenv("NETOS_XRAY_LOG_NETOS")+" internal-xray-run check "+path,
			os.Getenv("NETOS_XRAY_LOG_NETOS"), "internal-xray-run", "run", path)
	} else {
		args = append(args, binary, "run", "-c", path)
	}
	if out, err := run.Run(ctx, "systemd-run", args...); err != nil {
		t.Fatal(out, err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Xray not listening")
	}
	for _, valid := range []bool{true, false, true} {
		if protocol == "vless" {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, clientTLS)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			identity := byte(0x11)
			if !valid {
				identity = 0xaa
			}
			targetPort := echo.Addr().(*net.TCPAddr).Port
			packet := append([]byte{0}, bytes.Repeat([]byte{identity}, 16)...)
			packet = append(packet, 0, 1, byte(targetPort>>8), byte(targetPort), 1, 127, 0, 0, 1)
			packet = append(packet, []byte("probe")...)
			_, err = c.Write(packet)
			if err != nil {
				c.Close()
				t.Fatal(err)
			}
			answer := make([]byte, 7)
			n, readErr := io.ReadFull(c, answer)
			c.Close()
			if valid && (readErr != nil || !bytes.Equal(answer, []byte{0, 0, 'p', 'r', 'o', 'b', 'e'})) {
				t.Fatal("VLESS echo failed", readErr)
			}
			if !valid && bytes.Contains(answer[:n], []byte("probe")) {
				t.Fatal("invalid VLESS identity accepted")
			}
			continue
		}
		password := "log-password"
		if !valid {
			password = "wrong"
		}
		dialer, err := proxy.SOCKS5("tcp", address, &proxy.Auth{User: "log-user", Password: password}, &net.Dialer{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, err := dialer.Dial("tcp", echo.Addr().String())
		if !valid {
			if err == nil {
				c.Close()
				t.Fatal("wrong password accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Write([]byte("probe"))
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		answer := make([]byte, 5)
		_, err = io.ReadFull(c, answer)
		c.Close()
		if err != nil || string(answer) != "probe" {
			t.Fatal("echo", err)
		}
	}
	if out, err := run.Run(ctx, "systemctl", "stop", unit); err != nil {
		t.Fatal(out, err)
	}
	if _, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
		t.Fatal(err)
	}
	if protocol == "vless" {
		journal, err := run.Run(ctx, "journalctl", "-u", unit, "--since=@"+strconv.FormatInt(from.Unix(), 10), "--no-pager", "-o", "cat")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(journal, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") || !strings.Contains(journal, "invalid request user id: [скрыто]") {
			t.Fatal("raw journal credential redaction failed")
		}
	}
	st, err := store.Open(filepath.Join(root, "read.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{Store: st, StorageRunner: run}
	period := "from=" + url.QueryEscape(from.Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(time.Now().UTC().Format(time.RFC3339Nano)) + "&object=srv993"
	p := readAllJournalPages(t, s, "vpn", period)
	if len(p.Entries) != 3 {
		t.Fatal("missing Xray events", len(p.Entries))
	}
	failures := 0
	for _, e := range p.Entries {
		user := ""
		if protocol == "vless" && e.Result == "success" {
			user = "log-probe/peer"
		}
		if e.Protocol != "xray" || e.Server != "srv993" || e.Address != "127.0.0.1" || e.User != user {
			t.Fatal(e)
		}
		if e.Result == "failure" {
			failures++
		}
	}
	if failures != 1 {
		t.Fatal(failures)
	}
	all, code := allPageRequest(t, s, filepath.Join(root, "dns.log"), period+"&result=failure")
	if code != 200 || len(all.Entries) != 1 || all.Entries[0].Source != "vpn" {
		t.Fatal(code, all)
	}
	services := readAllJournalPages(t, s, "services", period)
	for _, e := range services.Entries {
		if strings.Contains(e.Message, " accepted ") || strings.Contains(e.Message, " rejected ") {
			t.Fatal("access in services")
		}
	}
	t.Logf("generated %s config: two real echo connections, one auth rejection; journald/VPN/General/Services PASS", protocol)
}

//go:build linux

package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
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
	t.Run("http", func(t *testing.T) { testXrayAccessJournal(t, false, true, "http") })
	t.Run("trojan", func(t *testing.T) { testXrayAccessJournal(t, false, true, "trojan") })
	t.Run("vmess", func(t *testing.T) { testXrayAccessJournal(t, false, true, "vmess") })
	t.Run("shadowsocks", func(t *testing.T) { testXrayAccessJournal(t, false, true, "shadowsocks") })
	t.Run("hysteria", func(t *testing.T) { testXrayAccessJournal(t, false, true, "hysteria") })
	t.Run("reality", func(t *testing.T) { testXrayAccessJournal(t, false, true, "reality") })
	t.Run("wireguard", func(t *testing.T) { testXrayAccessJournal(t, false, true, "wireguard") })
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
	if protocol == "reality" {
		fixture := profileTestServer(protocol)
		for _, key := range []string{"private_key", "server_names", "short_ids", "flow"} {
			server.Config[key] = fixture.Config[key]
		}
		camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "camouflage") }))
		camouflage.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		camouflage.EnableHTTP2 = true
		camouflage.StartTLS()
		defer camouflage.Close()
		server.Config["destination"] = camouflage.Listener.Addr().String()
	}
	if protocol == "shadowsocks" {
		server.Config["method"] = "aes-256-gcm"
	}
	server.Peers[0].Credentials["uuid"] = "11111111-1111-1111-1111-111111111111"
	if protocol == "wireguard" {
		server.Config["wg_private_key"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'s'}, 32))
		clientKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'c'}, 32))
		public, err := xrayPublicKey(clientKey)
		if err != nil {
			t.Fatal(err)
		}
		server.Peers[0].Address = "10.97.0.2"
		server.Peers[0].Credentials = map[string]string{"private_key": clientKey, "public_key": public}
	}
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
	profileTarget := echo.Addr().String()
	if protocol == "wireguard" {
		// A loopback destination belongs to the client's nested IP stack.
		// Route a test address through the tunnel, then terminate it locally.
		profileTarget = net.JoinHostPort("198.18.0.1", strconv.Itoa(echo.Addr().(*net.TCPAddr).Port))
		for _, raw := range doc["outbounds"].([]any) {
			outbound := raw.(map[string]any)
			if outbound["tag"] == "direct" {
				outbound["settings"].(map[string]any)["redirect"] = echo.Addr().String()
			}
		}
	}
	// Keep this generated-config test isolated from public interfaces and /run.
	doc["inbounds"].([]any)[0].(map[string]any)["listen"] = "127.0.0.1"
	doc["api"].(map[string]any)["listen"] = filepath.Join(root, "stats.sock")
	var clientTLS *tls.Config
	var clientPin string
	if protocol == "vless" || protocol == "trojan" || protocol == "hysteria" {
		cert, key, _, err := tlsutil.EnsureSelfSignedForNames(root, "localhost", "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		certPEM, err := os.ReadFile(cert)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certPEM) {
			t.Fatal("invalid test certificate")
		}
		block, _ := pem.Decode(certPEM)
		digest := sha256.Sum256(block.Bytes)
		clientPin = hex.EncodeToString(digest[:])
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
		if protocol == "shadowsocks" || protocol == "hysteria" || protocol == "reality" || protocol == "wireguard" {
			// An empty TCP probe itself produces an authentication rejection.
			flags := "-ltn"
			if protocol == "hysteria" || protocol == "wireguard" {
				flags = "-lun"
			}
			out, err := run.Run(ctx, "ss", "-H", flags, "sport", "=", strconv.Itoa(port))
			if err != nil {
				t.Fatal(out, err)
			}
			if strings.TrimSpace(out) != "" {
				ready = true
				break
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
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
		if protocol == "vmess" || protocol == "shadowsocks" || protocol == "hysteria" || protocol == "reality" || protocol == "wireguard" {
			probeXrayProfileLogConnection(t, binary, server, profileTarget, clientPin, valid)
			continue
		}
		if protocol == "trojan" {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, clientTLS)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			password := "log-password"
			if !valid {
				password = "qa-trojan-invalid-secret"
			}
			digest := sha256.Sum224([]byte(password))
			targetPort := echo.Addr().(*net.TCPAddr).Port
			packet := []byte(hex.EncodeToString(digest[:]) + "\r\n")
			packet = append(packet, 1, 1, 127, 0, 0, 1, byte(targetPort>>8), byte(targetPort), '\r', '\n')
			packet = append(packet, []byte("probe")...)
			if _, err = c.Write(packet); err != nil {
				c.Close()
				t.Fatal(err)
			}
			answer := make([]byte, 5)
			n, readErr := io.ReadFull(c, answer)
			c.Close()
			if valid && (readErr != nil || string(answer) != "probe") {
				t.Fatal("Trojan echo", readErr)
			}
			if !valid && bytes.Contains(answer[:n], []byte("probe")) {
				t.Fatal("wrong Trojan password accepted")
			}
			continue
		}
		if protocol == "http" {
			c, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			password := "log-password"
			if !valid {
				password = "wrong"
			}
			target := echo.Addr().String()
			request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("log-user:"+password)) + "\r\n\r\n"
			if _, err = io.WriteString(c, request); err != nil {
				c.Close()
				t.Fatal(err)
			}
			reader := bufio.NewReader(c)
			response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
			if err != nil {
				c.Close()
				t.Fatal(err)
			}
			if !valid {
				c.Close()
				if response.StatusCode != http.StatusProxyAuthRequired {
					t.Fatal("wrong password response", response.StatusCode)
				}
				continue
			}
			if response.StatusCode != http.StatusOK {
				c.Close()
				t.Fatal(response.StatusCode)
			}
			if _, err = io.WriteString(c, "probe"); err != nil {
				c.Close()
				t.Fatal(err)
			}
			answer := make([]byte, 5)
			_, err = io.ReadFull(reader, answer)
			c.Close()
			if err != nil || string(answer) != "probe" {
				t.Fatal("HTTP CONNECT echo", err)
			}
			continue
		}
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
	if protocol == "http" {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "probe") }))
		defer target.Close()
		c, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		u := strings.Replace(target.URL, "http://", "http://qa-url:qa-url-secret@", 1) + "/qa-private-path?token=qa-query-secret"
		request := "GET " + u + " HTTP/1.1\r\nHost: " + strings.TrimPrefix(target.URL, "http://") + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("log-user:log-password")) + "\r\nConnection: close\r\n\r\n"
		if _, err = io.WriteString(c, request); err != nil {
			c.Close()
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		c.Close()
		if err != nil || response.StatusCode != 200 || string(body) != "probe" {
			t.Fatal("HTTP absolute URL probe", response.StatusCode, err)
		}
	}
	if out, err := run.Run(ctx, "systemctl", "stop", unit); err != nil {
		t.Fatal(out, err)
	}
	if _, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
		t.Fatal(err)
	}
	if protocol == "vless" || protocol == "http" || protocol == "trojan" || protocol == "vmess" || protocol == "shadowsocks" || protocol == "hysteria" || protocol == "reality" || protocol == "wireguard" {
		journal, err := run.Run(ctx, "journalctl", "-u", unit, "--since=@"+strconv.FormatInt(from.Unix(), 10), "--no-pager", "-o", "cat")
		if err != nil {
			t.Fatal(err)
		}
		if protocol == "vless" && (strings.Contains(journal, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") || !strings.Contains(journal, "invalid request user id: [скрыто]")) {
			t.Fatal("raw journal credential redaction failed")
		}
		if protocol == "http" {
			for _, secret := range []string{"qa-url", "qa-private-path", "qa-query-secret", "log-password"} {
				if strings.Contains(journal, secret) {
					t.Fatal("HTTP secret reached raw journal", secret)
				}
			}
		}
		if protocol == "trojan" {
			for _, password := range []string{"log-password", "qa-trojan-invalid-secret"} {
				digest := sha256.Sum224([]byte(password))
				if strings.Contains(journal, password) || strings.Contains(journal, hex.EncodeToString(digest[:])) {
					t.Fatal("Trojan credential reached journal")
				}
			}
		}
		if protocol == "vmess" || protocol == "reality" {
			for _, uuid := range []string{server.Peers[0].Credentials["uuid"], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"} {
				if strings.Contains(journal, uuid) {
					t.Fatal(protocol, "credential reached journal")
				}
			}
		}
		if protocol == "reality" && strings.Contains(journal, server.Config["private_key"].(string)) {
			t.Fatal("Reality private key reached journal")
		}
		if protocol == "wireguard" {
			for _, key := range []string{server.Config["wg_private_key"].(string), server.Peers[0].Credentials["private_key"], base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'b'}, 32))} {
				if strings.Contains(journal, key) {
					t.Fatal("WireGuard private key reached journal")
				}
			}
		}
		if protocol == "shadowsocks" || protocol == "hysteria" {
			for _, password := range []string{"log-password", "qa-" + protocol + "-invalid-secret"} {
				if strings.Contains(journal, password) {
					t.Fatal(protocol, "credential reached journal")
				}
			}
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
	wantEvents := 3
	if protocol == "hysteria" || protocol == "wireguard" {
		wantEvents = 2 // Failed transport authentication is not an Xray access record.
	}
	if len(p.Entries) != wantEvents {
		t.Fatal("missing Xray events", len(p.Entries))
	}
	failures := 0
	for _, e := range p.Entries {
		user := ""
		if (protocol == "vless" || protocol == "trojan" || protocol == "vmess" || protocol == "shadowsocks" || protocol == "hysteria" || protocol == "reality") && e.Result == "success" {
			user = "log-probe/peer"
		}
		address := "127.0.0.1"
		if protocol == "wireguard" {
			address = server.Peers[0].Address
		}
		if e.Protocol != "xray" || e.Server != "srv993" || e.Address != address || e.User != user {
			t.Fatal(e)
		}
		if e.Result == "failure" {
			failures++
		}
	}
	wantFailures := 1
	if protocol == "http" || protocol == "hysteria" || protocol == "wireguard" {
		wantFailures = 0
	} // These authentication refusals have no access event in Xray.
	if failures != wantFailures {
		t.Fatal(failures)
	}
	all, code := allPageRequest(t, s, filepath.Join(root, "dns.log"), period+"&result=failure")
	if code != 200 || len(all.Entries) != wantFailures || (wantFailures > 0 && all.Entries[0].Source != "vpn") {
		t.Fatal(code, all)
	}
	services := readAllJournalPages(t, s, "services", period)
	warning := false
	for _, e := range services.Entries {
		if strings.Contains(e.Message, " accepted ") || strings.Contains(e.Message, " rejected ") {
			t.Fatal("access in services")
		}
		if strings.Contains(e.Message, "[Warning] core: Xray") && e.Severity == "warning" {
			warning = true
		}
	}
	if worker && !warning {
		t.Fatal("real Xray diagnostic lost from Services")
	}
	if worker {
		general, status := allPageRequest(t, s, filepath.Join(root, "dns.log"), period+"&result=warning")
		found := 0
		for _, e := range general.Entries {
			if strings.Contains(e.Message, "[Warning] core: Xray") && e.Source == "services" {
				found++
			}
		}
		if status != 200 || found != 1 {
			t.Fatal("canonical diagnostic missing or duplicated", status, found)
		}
	}
	t.Logf("generated %s config: two real echo connections, one invalid-credential attempt; HTTP additionally GET with private URL; observed rejection events=%d; journald/VPN/General/Services PASS", protocol, failures)
}

func probeXrayProfileLogConnection(t *testing.T, binary string, server config.VPNServer, target, pin string, valid bool) {
	t.Helper()
	peer := server.Peers[0]
	protocol := server.Config["protocol"].(string)
	credential, invalid := "uuid", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	if protocol == "shadowsocks" || protocol == "hysteria" {
		credential, invalid = "password", "qa-"+protocol+"-invalid-secret"
	}
	if protocol == "wireguard" {
		credential, invalid = "private_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'b'}, 32))
	}
	peer.Credentials = map[string]string{credential: peer.Credentials[credential]}
	if !valid {
		peer.Credentials[credential] = invalid
	}
	server.Config["public_endpoint"] = net.JoinHostPort("127.0.0.1", strconv.Itoa(server.Port))
	var profile xrayProfile
	var err error
	if protocol == "wireguard" {
		public, keyErr := xrayPublicKey(server.Config["wg_private_key"].(string))
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		// Keep the nested WireGuard client in userspace; kernel TUN changes host sysctls.
		profile.Config = map[string]any{
			"log":      map[string]any{"loglevel": "warning"},
			"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
			"outbounds": []any{map[string]any{"protocol": "wireguard", "settings": map[string]any{
				"noKernelTun": true, "secretKey": peer.Credentials["private_key"], "address": []string{peer.Address + "/32"},
				"peers": []any{map[string]any{"publicKey": public, "endpoint": server.Config["public_endpoint"], "allowedIPs": []string{"0.0.0.0/0"}}},
			}}},
		}
	} else {
		profile, err = xrayClientProfile(server, peer, pin)
	}
	if err != nil {
		t.Fatal(err)
	}
	if protocol == "hysteria" || protocol == "reality" {
		// Client-side evidence distinguishes auth refusal from a transport timeout.
		profile.Config["log"].(map[string]any)["loglevel"] = "info"
	}
	if protocol == "wireguard" {
		profile.Config["log"].(map[string]any)["loglevel"] = "debug"
	}
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	profile.Config["inbounds"].([]any)[0].(map[string]any)["port"] = port
	data, err := json.Marshal(profile.Config)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "client.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(root, "client.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	lifetime, readTimeout := 10*time.Second, 2*time.Second
	if protocol == "reality" {
		// Reality can wait five seconds for its asynchronous target-record probe
		// even after the listening socket is ready. Do not retry/discard events.
		lifetime, readTimeout = 15*time.Second, 7*time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), lifetime)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "run", "-config", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal(protocol, "client not listening")
	}
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	conn, err := dialer.(proxy.ContextDialer).DialContext(dialCtx, "tcp", target)
	if err != nil {
		t.Fatal("client SOCKS connection", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(readTimeout))
	if _, err = conn.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, 5)
	n, readErr := io.ReadFull(conn, answer)
	if valid && (readErr != nil || string(answer) != "probe") {
		data, _ := os.ReadFile(filepath.Join(root, "client.log"))
		t.Fatalf("%s echo: %v\n%s", protocol, readErr, data)
	}
	if !valid && bytes.Contains(answer[:n], []byte("probe")) {
		t.Fatal(protocol, "invalid credential accepted")
	}
	if !valid && protocol == "hysteria" {
		data, err := os.ReadFile(filepath.Join(root, "client.log"))
		if err != nil || !bytes.Contains(data, []byte("auth failed code")) {
			t.Fatalf("missing client evidence of Hysteria authentication refusal: %v\n%s", err, data)
		}
	}
	if protocol == "wireguard" {
		data, err := os.ReadFile(filepath.Join(root, "client.log"))
		initiated := bytes.Contains(data, []byte("Sending handshake initiation"))
		responded := bytes.Contains(data, []byte("Received handshake response"))
		if err != nil || !initiated || responded != valid {
			t.Fatalf("WireGuard handshake evidence: valid=%v, error=%v\n%s", valid, err, data)
		}
	}
}

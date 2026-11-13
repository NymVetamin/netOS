//go:build linux

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationXrayLiveResourceJournal(t *testing.T) {
	xray, helper := os.Getenv("NETOS_XRAY_LOG_BINARY"), os.Getenv("NETOS_XRAY_LOG_NETOS")
	if xray == "" || helper == "" {
		t.Skip("requires authorized Linux and verified binaries")
	}
	run := &system.Exec{Timeout: 15 * time.Second, MaxOutputBytes: 1 << 20}
	ctx := context.Background()
	const unit = "netos-xray-srv995.service"
	state, err := run.Run(ctx, "systemctl", "show", unit, "-p", "LoadState", "--value")
	if err != nil || strings.TrimSpace(state) != "not-found" {
		t.Fatal("unit occupied", state, err)
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
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(2 * time.Second)); io.Copy(c, c) }()
		}
	}()
	server := config.VPNServer{ID: "s", Index: 995, Name: "Resource test", Enabled: true, Type: "xray", Port: port, DefaultChannel: "direct", Config: map[string]any{"protocol": "vless"}, Peers: []config.VPNPeer{{ID: "a", Enabled: true, Credentials: map[string]string{"uuid": "11111111-1111-1111-1111-111111111111"}}}}
	cfg := config.Default()
	cfg.TrafficMonitor.Enabled = true
	cfg.VPNServers = []config.VPNServer{server}
	root := t.TempDir()
	raw, err := vpnservers.RenderXray(server, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	in := doc["inbounds"].([]any)[0].(map[string]any)
	in["listen"] = "127.0.0.1"
	// This test isolates the live resource pipeline; the separate API test
	// exercises generated VLESS TLS with certificate verification.
	in["streamSettings"] = map[string]any{"network": "tcp"}
	doc["api"].(map[string]any)["listen"] = filepath.Join(root, "stats.sock")
	raw, _ = json.Marshal(doc)
	conf := filepath.Join(root, "xray.json")
	if err = os.WriteFile(conf, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h, err := NewClientHistory(filepath.Join(root, "history.db"), nil, nil, func() *config.Config { return cfg })
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.enabled = true
	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); h.watchDNS(watchCtx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("journal watcher did not stop")
		}
	}()
	t.Cleanup(func() { run.Run(ctx, "systemctl", "stop", unit); run.Run(ctx, "systemctl", "reset-failed", unit) })
	if out, err := run.Run(ctx, "systemd-run", "--unit="+unit, "--collect", "--property=TemporaryFileSystem=/usr/local/bin:ro", "--property=BindReadOnlyPaths="+xray+":/usr/local/bin/xray", "--property=SyslogIdentifier=netos-xray", helper, "internal-xray-run", "run", conf); err != nil {
		t.Fatal(out, err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for deadline := time.Now().Add(5 * time.Second); ; {
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Xray did not listen")
		}
		time.Sleep(25 * time.Millisecond)
	}
	var sent int64
	connect := func() {
		t.Helper()
		c, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		p := echo.Addr().(*net.TCPAddr).Port
		packet := append([]byte{0}, bytes.Repeat([]byte{0x11}, 16)...)
		packet = append(packet, 0, 1, byte(p>>8), byte(p), 1, 127, 0, 0, 1, 'x')
		if _, err = c.Write(packet); err != nil {
			t.Fatal(err)
		}
		answer := make([]byte, 3)
		if _, err = io.ReadFull(c, answer); err != nil || !bytes.Equal(answer, []byte{0, 0, 'x'}) {
			t.Fatal("VLESS echo", err)
		}
		sent++
	}
	count := func() (int64, bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		var n int64
		lost := false
		for _, r := range h.resources {
			if r.Client != "vpn:s:a" || r.Domain != "127.0.0.1" || r.Source != "xray-ip" {
				t.Error("wrong attribution", r)
			}
			n += r.Count
		}
		for _, l := range h.limits {
			if l.Kind == "journal" {
				lost = true
			}
		}
		return n, lost
	}
	// Establish that the real --follow subscriber is attached, rather than
	// assuming a fixed startup sleep is enough on every system.
	for deadline := time.Now().Add(8 * time.Second); ; {
		connect()
		time.Sleep(100 * time.Millisecond)
		if n, _ := count(); n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("live journal subscription missed connections")
		}
	}
	warmups := sent
	started := time.Now()
	for i := 0; i < 1000; i++ {
		connect()
	}
	elapsed := time.Since(started)
	for deadline := time.Now().Add(5 * time.Second); ; {
		if n, lost := count(); n > warmups && lost {
			t.Logf("live helper/journald/watchDNS: attributed=%d; loss metadata present; 1000 real echo connections in %s", n, elapsed)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bounded producer loss was not reported to history")
		}
		time.Sleep(50 * time.Millisecond)
	}
	journal, err := run.Run(ctx, "journalctl", "-u", unit, "-n", "10", "--no-pager", "-o", "json", "--output-fields=SYSLOG_IDENTIFIER,_COMM,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_PID,MESSAGE")
	if err != nil || !strings.Contains(journal, `"netos-xray"`) || !strings.Contains(journal, `"netos"`) {
		t.Fatal("worker metadata absent", err)
	}
	t.Log("resource test uses actual Xray requests and real journal subscription; no synthetic log producer")
}

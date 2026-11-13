//go:build linux

package api

import (
	"context"
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
	"golang.org/x/net/proxy"
)

func TestIntegrationXrayAccessJournal(t *testing.T) {
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
	cfg := config.Default()
	cfg.TrafficMonitor.Enabled = true
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
	raw, _ = json.Marshal(doc)
	path := filepath.Join(root, "xray.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run.Run(ctx, "systemctl", "stop", unit); run.Run(ctx, "systemctl", "reset-failed", unit) })
	from := time.Now().Add(-time.Second).UTC()
	if out, err := run.Run(ctx, "systemd-run", "--unit="+unit, "--collect", "--property=StandardOutput=journal", "--property=StandardError=journal", binary, "run", "-c", path); err != nil {
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
		if e.Protocol != "xray" || e.Server != "srv993" || e.Address != "127.0.0.1" || e.User != "" {
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
	t.Log("generated SOCKS config: two real echo connections, one auth rejection; journald/VPN/General/Services PASS")
}

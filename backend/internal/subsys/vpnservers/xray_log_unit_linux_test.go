//go:build linux

package vpnservers

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"golang.org/x/net/proxy"
)

func TestIntegrationXrayGeneratedLogUnit(t *testing.T) {
	xray, helper := os.Getenv("NETOS_XRAY_LOG_BINARY"), os.Getenv("NETOS_XRAY_LOG_NETOS")
	if xray == "" || helper == "" {
		t.Skip("requires authorized root Linux and both verified binaries")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	ctx := context.Background()
	run := &system.Exec{Timeout: 15 * time.Second, MaxOutputBytes: 1 << 20}
	const unit = "netos-xray-srv994.service"
	const unitPath = "/run/systemd/system/" + unit
	const dropDir = unitPath + ".d"
	const runtimeDir = "/run/netos-xray-srv994"
	state, err := run.Run(ctx, "systemctl", "show", unit, "-p", "LoadState", "--value")
	if err != nil || strings.TrimSpace(state) != "not-found" {
		t.Fatal("unit occupied", state, err)
	}
	for _, p := range []string{unitPath, dropDir, runtimeDir} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatal("path occupied", p, err)
		}
	}
	root, err := os.MkdirTemp("/var/lib", "netos-xray-log-unit-")
	if err != nil {
		t.Fatal(err)
	}
	createdUnit, createdDrop := false, false
	t.Cleanup(func() {
		if createdUnit {
			run.Run(ctx, "systemctl", "stop", unit)
			run.Run(ctx, "systemctl", "reset-failed", unit)
			os.Remove(unitPath)
		}
		if createdDrop {
			os.Remove(filepath.Join(dropDir, "qa.conf"))
			os.Remove(dropDir)
		}
		run.Run(ctx, "systemctl", "daemon-reload")
		os.RemoveAll(root)
	})
	// Sources remain visible with PrivateTmp/ProtectHome and executable on
	// hosts where /run is noexec. The private directory is removed on cleanup.
	for name, source := range map[string]string{"xray": xray, "netos": helper} {
		in, err := os.Open(source)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if err != nil {
			in.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(out, in)
		in.Close()
		closeErr := out.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal(copyErr, closeErr)
		}
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
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(2 * time.Second)); io.Copy(c, c) }()
		}
	}()
	server := config.VPNServer{ID: "unit-test", Index: 994, Name: "Log unit test", Enabled: true, Type: "xray", Port: port, DefaultChannel: "direct", Config: map[string]any{"protocol": "socks", "listen": "127.0.0.1"}, Peers: []config.VPNPeer{{ID: "peer", Enabled: true, Credentials: map[string]string{"username": "unit-user", "password": "unit-password"}}}}
	cfg := config.Default()
	cfg.TrafficMonitor.Enabled = false
	data, err := RenderXray(server, cfg)
	if err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "xray.json")
	if err = os.WriteFile(conf, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(dropDir, 0700); err != nil {
		t.Fatal(err)
	}
	createdDrop = true
	drop := "[Service]\nTemporaryFileSystem=/usr/local/bin:ro\nBindReadOnlyPaths=" + filepath.Join(root, "xray") + ":/usr/local/bin/xray " + filepath.Join(root, "netos") + ":/usr/local/bin/netos\n"
	if err = os.WriteFile(filepath.Join(dropDir, "qa.conf"), []byte(drop), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(unitPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	createdUnit = true
	_, err = f.WriteString(renderXrayUnit(server, conf))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	command := func(args ...string) string {
		t.Helper()
		out, err := run.Run(ctx, "systemctl", args...)
		if err != nil {
			t.Fatal(args, out, err)
		}
		return strings.TrimSpace(out)
	}
	command("daemon-reload")
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	checkEcho := func() {
		t.Helper()
		ready := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				c.Close()
				ready = true
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !ready {
			journal, _ := run.Run(ctx, "journalctl", "-u", unit, "-n", "20", "--no-pager")
			t.Fatal("not listening", journal)
		}
		dial, err := proxy.SOCKS5("tcp", address, &proxy.Auth{User: "unit-user", Password: "unit-password"}, &net.Dialer{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, err := dial.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = c.Write([]byte("echo")); err != nil {
			t.Fatal(err)
		}
		answer := make([]byte, 4)
		if _, err = io.ReadFull(c, answer); err != nil || string(answer) != "echo" {
			t.Fatal("echo failed", err)
		}
	}
	command("start", unit)
	checkEcho()
	for property, want := range map[string]string{"PrivateTmp": "yes", "ProtectHome": "yes", "ProtectSystem": "strict", "NoNewPrivileges": "yes"} {
		if got := command("show", unit, "-p", property, "--value"); got != want {
			t.Fatal(property, got)
		}
	}
	if _, err = os.Stat(XrayStatsSocket(server)); err != nil {
		t.Fatal("stats socket missing", err)
	}
	pid := command("show", unit, "-p", "MainPID", "--value")
	command("restart", unit)
	checkEcho()
	if got := command("show", unit, "-p", "MainPID", "--value"); got == pid || got == "0" {
		t.Fatal("restart failed", got)
	}
	if err = os.WriteFile(conf, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = run.Run(ctx, "systemctl", "restart", unit); err == nil {
		t.Fatal("invalid configuration passed ExecStartPre")
	}
	if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("child survived failed check")
	}
	if err = os.WriteFile(conf, data, 0600); err != nil {
		t.Fatal(err)
	}
	command("reset-failed", unit)
	command("start", unit)
	checkEcho()
	command("stop", unit)
	if result := command("show", unit, "-p", "Result", "--value"); result != "success" {
		t.Fatal("normal stop reported as failure", result)
	}
	if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("child survived stop")
	}
	if _, err = os.Lstat(runtimeDir); !os.IsNotExist(err) {
		t.Fatal("runtime directory retained", err)
	}
	t.Log("full generated unit: hardening, stats socket, restart, failed check, repair/retry, child stop and runtime cleanup PASS")
}

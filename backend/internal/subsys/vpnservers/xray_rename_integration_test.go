//go:build linux

package vpnservers

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"golang.org/x/net/proxy"
)

func TestIntegrationXrayServerRename(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and NETOS_INTEGRATION=1")
	}
	if _, err := os.Stat("/usr/local/bin/xray"); err != nil {
		t.Skip("Xray unavailable")
	}
	root, err := os.MkdirTemp("/var/lib/netos", "integration-xray-rename-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	s := New(system.NewExec(), root)
	ctx := context.Background()
	server := config.VPNServer{ID: "rename-test", Name: "Before", Index: 995, Type: "xray", Enabled: true, Port: 51995, Subnet: "10.253.95.1/24", DefaultChannel: "direct",
		Config: map[string]any{"protocol": "socks", "listen": "127.0.0.1"},
		Peers:  []config.VPNPeer{{ID: "peer", Enabled: true, Address: "10.253.95.2", Credentials: map[string]string{"username": "test", "password": "test-password"}}}}
	_, unitPath := s.xrayPaths(server)
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatal("test unit already exists")
	}
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "xray", Installed: true}}
	cfg.VPNServers = []config.VPNServer{server}
	defer s.cleanupXray(ctx, server)
	if _, err := s.applyXray(ctx, cfg, server, false); err != nil {
		t.Fatal(err)
	}
	stamp, err := s.Runner.Run(ctx, "systemctl", "show", xrayUnitName(server), "-p", "ActiveEnterTimestampMonotonic", "--value")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:51995", &proxy.Auth{User: "test", Password: "test-password"}, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, err = dialer.Dial("tcp", listener.Addr().String())
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echo := func(c net.Conn) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("alive")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(c, got); err != nil || string(got) != "alive" {
			t.Fatalf("TCP interrupted: %q %v", got, err)
		}
	}
	echo(conn)
	for _, name := range []string{"After", "After", "Before"} {
		server.Name = name
		cfg.VPNServers[0] = server
		if _, err := s.applyXray(ctx, cfg, server, true); err != nil {
			t.Fatal(err)
		}
		got, err := s.Runner.Run(ctx, "systemctl", "show", xrayUnitName(server), "-p", "ActiveEnterTimestampMonotonic", "--value")
		if err != nil || got != stamp {
			t.Fatalf("rename restarted server: %v", err)
		}
		got, err = s.Runner.Run(ctx, "systemctl", "show", xrayUnitName(server), "-p", "Description", "--value")
		if err != nil || !strings.Contains(got, name) {
			t.Fatal("description not updated")
		}
		echo(conn)
		fresh, err := dialer.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		echo(fresh)
		fresh.Close()
	}
	server.Config["sniffing"] = true
	cfg.VPNServers[0] = server
	if _, err := s.applyXray(ctx, cfg, server, true); err != nil {
		t.Fatal(err)
	}
	got, err := s.Runner.Run(ctx, "systemctl", "show", xrayUnitName(server), "-p", "ActiveEnterTimestampMonotonic", "--value")
	if err != nil || got == stamp {
		t.Fatalf("real configuration change did not restart server: %v", err)
	}
}

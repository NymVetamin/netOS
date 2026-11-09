//go:build linux

package vpnservers

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationWireGuardExitGuardRestore(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated root integration only")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == "" || self == host {
		t.Fatal("refusing host namespace")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("iptables", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("iptables %v: %v %s", args, err, out)
		}
		return string(out)
	}
	server := config.VPNServer{Index: 1, Enabled: true, Type: "wireguard", Peers: []config.VPNPeer{
		{Enabled: true, UseAsChannel: true, Address: "10.8.0.2"},
		{Enabled: true, Address: "10.8.0.3"},
	}}
	s := New(system.NewExec(), t.TempDir())
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := s.protectWireGuardExit(ctx, server); err != nil {
			t.Fatal(err)
		}
	}
	before := run("-t", "mangle", "-S", "NETOS-WGEXIT1")
	if !strings.Contains(before, "-s 10.8.0.2/31 -j RETURN") {
		t.Fatal(before)
	}
	jump := run("-t", "mangle", "-S", "PREROUTING")
	if strings.Count(jump, "-j NETOS-WGEXIT1") != 1 {
		t.Fatal("duplicate protection jump", jump)
	}
	server.Peers[0].Address = "10.8.0.2/33"
	if _, err := s.applyWireGuard(ctx, server, false, true); err == nil {
		t.Fatal("accepted invalid guard")
	}
	if after := run("-t", "mangle", "-S", "NETOS-WGEXIT1"); after != before {
		t.Fatal("failed restore changed protection", after)
	}
	if _, err := exec.Command("ip", "link", "show", "wg-srv1").Output(); err == nil {
		t.Fatal("activated interface after protection failure")
	}
	server.Peers[0].Address = "10.8.0.2"
	server.Peers[1].Enabled = false
	if err := s.protectWireGuardExit(ctx, server); err != nil {
		t.Fatal(err)
	}
	after := run("-t", "mangle", "-S", "NETOS-WGEXIT1")
	if !strings.Contains(after, "-s 10.8.0.2/32 -j RETURN") || strings.Contains(after, "/31") {
		t.Fatal("retry retained disabled address", after)
	}
	if run("-t", "mangle", "-S", "PREROUTING") != jump {
		t.Fatal("retry changed protection jump")
	}
}

//go:build linux

package qos

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationCAKELifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, command := range []string{"ip", "tc", "modprobe"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
	ctx := context.Background()
	runner := system.NewExec()
	const device = "nqos-test0"
	const peer = "nqos-test1"
	const ifb = "ifb-netos-91"
	for _, name := range []string{device, peer, ifb} {
		if _, err := runner.Run(ctx, "ip", "link", "show", "dev", name); err == nil {
			t.Skipf("refusing to reuse existing interface %s", name)
		}
	}
	_, _ = runner.Run(ctx, "modprobe", "ifb")
	_, _ = runner.Run(ctx, "modprobe", "sch_cake")
	if _, err := runner.Run(ctx, "ip", "link", "add", "name", device, "type", "veth", "peer", "name", peer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(context.Background(), "tc", "qdisc", "del", "dev", device, "root")
		_, _ = runner.Run(context.Background(), "tc", "qdisc", "del", "dev", device, "ingress")
		_, _ = runner.Run(context.Background(), "ip", "link", "del", "dev", ifb)
		_, _ = runner.Run(context.Background(), "ip", "link", "del", "dev", device)
	})
	if _, err := runner.Run(ctx, "ip", "link", "set", "dev", device, "up"); err != nil {
		t.Fatal(err)
	}

	s := New(runner, t.TempDir())
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "uplink", Name: device, Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "test-wan", Index: 91, Interface: "uplink", Proto: "dhcp", Enabled: true}}
	cfg.QoS = config.QoS{Enabled: true, WANs: []config.QoSWAN{{WAN: "test-wan", UploadKbit: 8000, DownloadKbit: 12000, Diffserv: "diffserv4"}}}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{device, ifb} {
		out, err := runner.Run(ctx, "tc", "qdisc", "show", "dev", name)
		if err != nil || !strings.Contains(out, "cake") {
			t.Fatalf("CAKE is not active on %s: %s (%v)", name, out, err)
		}
	}
	// A second apply must reuse the owned IFB instead of colliding with it.
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.QoS.Enabled = false
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, "ip", "link", "show", "dev", ifb); err == nil {
		t.Fatal("owned IFB remained after disabling QoS")
	}
}

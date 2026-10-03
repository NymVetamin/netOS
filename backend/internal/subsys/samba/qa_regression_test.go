package samba

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type mountedRunner struct {
	*fakeRunner
	mount string
}

func (r *mountedRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "nsenter" && strings.Join(args, " ") == "--target 1 --mount -- findmnt -rn -o TARGET,FSTYPE" {
		return r.mount + " exfat\n", nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestBusyVolumeDoesNotStopAutomount(t *testing.T) {
	c := fixture()
	r := &mountedRunner{newRunner(), MountPath(c.Samba.Volumes[0])}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	r.fail = "nsenter --target 1 --mount -- umount --"
	if err := s.removeVolume(context.Background(), c.Samba.Volumes[0]); err == nil {
		t.Fatal("busy filesystem detached")
	}
	for _, call := range r.calls {
		if strings.Contains(call, "systemctl") {
			t.Fatalf("automount touched before successful unmount: %s", call)
		}
	}
}

func TestDisabledSambaIgnoresHostname(t *testing.T) {
	c := config.Default()
	s := New(nil, t.TempDir())
	before := s.stamp(c)
	c.System.Hostname = "renamed-router"
	if !bytes.Equal(before, s.stamp(c)) {
		t.Fatal("disabled Samba makes hostname-only changes disruptive")
	}
}

func TestVPNOnlyBindingAndPrivateRuntime(t *testing.T) {
	c := fixture()
	c.Samba.Networks = nil
	c.Samba.VPNs = []string{"vpn"}
	c.VPNServers = []config.VPNServer{{ID: "vpn", Index: 1, Enabled: true, Type: "wireguard", Subnet: "198.19.70.1/24"}}
	text, err := Render(c, "/var/lib/netos/generated")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"198.19.70.1/24", "ncalrpc dir = /run/netos-samba/ncalrpc", "bind interfaces only = yes", "hosts deny = ALL"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if !strings.Contains(sambaUnit("/var/lib/netos/generated"), "RuntimeDirectory=netos-samba\n") {
		t.Fatal("runtime parent missing after reboot")
	}
}

func TestActiveSambaWithOnlyLoopbackIsRepaired(t *testing.T) {
	r := newRunner()
	s := testSubsystem(t, r)
	c := fixture()
	c.Samba.Discovery = true
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	r.listeners = "LISTEN 0 50 127.0.0.1:445 0.0.0.0:*\n"
	if err := s.Health(ctx, c); err == nil {
		t.Fatal("active service without LAN listener reported healthy")
	}
	actions, err := s.Plan(c, c)
	if err != nil || len(actions) == 0 {
		t.Fatal("missing LAN listener not planned for repair")
	}
	r.calls = nil
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("missing listener not repaired")
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-wsdd.service") {
		t.Fatal("discovery started before LAN readiness not repaired")
	}
	if err := s.Health(ctx, c); err != nil {
		t.Fatal(err)
	}
}

type vpnAddressRunner struct {
	*fakeRunner
	address string
}

func (r *vpnAddressRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "ip" && strings.Join(args, " ") == "-o -4 addr show" {
		return r.address, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestNewVPNAddressRepairsOnlySelectedSambaListener(t *testing.T) {
	r := &vpnAddressRunner{fakeRunner: newRunner()}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	c := fixture()
	c.Samba.VPNs = []string{"oc"}
	c.VPNServers = []config.VPNServer{{ID: "oc", Index: 30, Enabled: true, Type: "ocserv", Subnet: "10.93.0.1/24"}}
	if err := s.Apply(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := s.ReconcileVPNListeners(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("restarted Samba before the VPN interface existed")
	}
	r.address = "17: vpns30 inet 10.93.0.1/32 scope global vpns30\n"
	r.calls = nil
	if err := s.ReconcileVPNListeners(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("missing VPN listener was not repaired")
	}
	r.listeners += "LISTEN 0 50 10.93.0.1:445 0.0.0.0:*\n"
	r.calls = nil
	if err := s.ReconcileVPNListeners(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("healthy VPN listener caused repeated restart")
	}
}

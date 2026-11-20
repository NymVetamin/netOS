package samba

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type firstEnableRunner struct {
	*fakeRunner
	stateDir string
}

func (r *firstEnableRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "testparm" {
		info, err := os.Stat(filepath.Join(r.stateDir, "samba"))
		if err != nil || !info.IsDir() {
			return "", fmt.Errorf("Samba state directory missing at validation: %w", err)
		}
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestFirstSambaEnablePreparesValidationDirectory(t *testing.T) {
	s := New(nil, t.TempDir())
	s.UnitDir = t.TempDir()
	s.Runner = &firstEnableRunner{fakeRunner: newRunner(), stateDir: s.StateDir}
	if err := s.Apply(context.Background(), fixture()); err != nil {
		t.Fatal(err)
	}
}

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

func TestPresentVPNAddressesMatchesAddressAndInterface(t *testing.T) {
	r := &vpnAddressRunner{fakeRunner: newRunner(), address: "1: wg-srv1: inet 10.0.0.1/32\n2: vpns20 inet 10.0.0.1\n3: wg-srv30 inet 10.0.0.1/24\n4: wg-srv3 inet 10.0.0.1/99\n"}
	s := New(r, t.TempDir())
	c := config.Default()
	for i, kind := range []string{"wireguard", "ocserv", "wireguard", "xray"} {
		id := fmt.Sprint(i + 1)
		c.VPNServers = append(c.VPNServers, config.VPNServer{ID: id, Index: i + 1, Type: kind, Enabled: true, Subnet: "10.0.0.1/24"})
		c.Samba.VPNs = append(c.Samba.VPNs, id)
	}
	want := map[string]string{"1": "10.0.0.1:445", "2": "10.0.0.1:445"}
	got, err := s.presentVPNAddresses(context.Background(), c)
	if err != nil || !maps.Equal(got, want) {
		t.Fatalf("present=%v err=%v", got, err)
	}
	r.address = "1: wg-srv3 inet 10.0.0.1\n"
	got, err = s.presentVPNAddresses(context.Background(), c)
	if err != nil || !maps.Equal(got, map[string]string{"3": "10.0.0.1:445"}) {
		t.Fatalf("after address change: %v %v", got, err)
	}
}

func BenchmarkPresentVPNAddresses(b *testing.B) {
	for _, n := range []int{16, 128} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := config.Default()
			var output strings.Builder
			for i := 1; i <= n; i++ {
				id := fmt.Sprint(i)
				addr := fmt.Sprintf("10.0.%d.1/24", i)
				c.VPNServers = append(c.VPNServers, config.VPNServer{ID: id, Index: i, Type: "wireguard", Subnet: addr, Enabled: true})
				c.Samba.VPNs = append(c.Samba.VPNs, id)
				fmt.Fprintf(&output, "%d: wg-srv%d inet %s scope global\n", i, i, addr)
			}
			r := &vpnAddressRunner{fakeRunner: newRunner(), address: output.String()}
			s := New(r, b.TempDir())
			b.ReportAllocs()
			for b.Loop() {
				if got, err := s.presentVPNAddresses(context.Background(), c); err != nil || len(got) != n {
					b.Fatal(len(got), err)
				}
			}
		})
	}
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

func TestBarePPPAddressRepairsSelectedSambaListener(t *testing.T) {
	r := &vpnAddressRunner{fakeRunner: newRunner()}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	c := fixture()
	c.Samba.VPNs = []string{"l2tp"}
	c.VPNServers = []config.VPNServer{{ID: "l2tp", Index: 30, Enabled: true, Type: "l2tp", Subnet: "10.99.1.1/24"}}
	if err := s.Apply(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	r.address = "17: pp30-0a630102 inet 10.99.1.1 peer 10.99.1.2/32 scope global pp30-0a630102\n"
	r.calls = nil
	if err := s.ReconcileVPNListeners(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("bare PPP address did not repair missing listener")
	}
}

func TestL2TPSelectionBeforeFirstPPPDefersAddressBinding(t *testing.T) {
	r := &vpnAddressRunner{fakeRunner: newRunner()}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	c := fixture()
	c.Samba.VPNs = []string{"l2tp"}
	c.VPNServers = []config.VPNServer{{ID: "l2tp", Index: 30, Enabled: true, Type: "l2tp", Subnet: "10.99.1.1/24"}}
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(s.StateDir, "samba.conf")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "10.99.1.1/24") {
		t.Fatal("absent PPP address bound before first client")
	}
	if err := s.Health(ctx, c); err != nil {
		t.Fatalf("LAN must remain healthy before PPP: %v", err)
	}
	r.calls = nil
	if err := s.ReconcileVPNListeners(ctx, c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("absent PPP caused a restart")
	}
	r.address = "17: pp30-0a630102 inet 10.99.1.1 peer 10.99.1.2/32 scope global pp30-0a630102\n"
	r.calls = nil
	if err := s.ReconcileVPNListeners(ctx, c); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "10.99.1.1/24") || !strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("new PPP address did not update Samba config and listener")
	}
	r.address = ""
	s.nextVPNRepair = time.Time{}
	if err := s.ReconcileVPNListeners(ctx, c); err != nil {
		t.Fatal(err)
	}
	after, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "10.99.1.1/24") {
		t.Fatal("stale PPP address remains bound after disconnect")
	}
}

func TestVPNListenerUpdateValidatesBeforeReplacingWorkingSamba(t *testing.T) {
	r := &vpnAddressRunner{fakeRunner: newRunner()}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	c := fixture()
	c.Samba.VPNs = []string{"l2tp"}
	c.VPNServers = []config.VPNServer{{ID: "l2tp", Index: 30, Enabled: true, Type: "l2tp", Subnet: "10.99.1.1/24"}}
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.StateDir, "samba.conf")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r.address = "17: pp30-0a630102 inet 10.99.1.1 peer 10.99.1.2/32 scope global pp30-0a630102\n"
	r.fail = "testparm"
	r.calls = nil
	if err := s.ReconcileVPNListeners(ctx, c); err == nil {
		t.Fatal("invalid candidate accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("working Samba config or listener changed after failed validation")
	}
}

func TestPPPReconnectUpdatesBindingDuringListenerCooldown(t *testing.T) {
	r := &vpnAddressRunner{fakeRunner: newRunner()}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	c := fixture()
	c.Samba.VPNs = []string{"l2tp"}
	c.VPNServers = []config.VPNServer{{ID: "l2tp", Index: 30, Enabled: true, Type: "l2tp", Subnet: "10.99.1.1/24"}}
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{
		"17: pp30-0a630102 inet 10.99.1.1 peer 10.99.1.2/32 scope global pp30-0a630102\n",
		"",
		"18: pp30-0a630102 inet 10.99.1.1 peer 10.99.1.2/32 scope global pp30-0a630102\n",
	} {
		r.address = address
		r.calls = nil
		if err := s.ReconcileVPNListeners(ctx, c); err != nil {
			t.Fatal(err)
		}
		conf, err := os.ReadFile(filepath.Join(s.StateDir, "samba.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(conf), "10.99.1.1/24") != (address != "") {
			t.Fatalf("PPP state change was suppressed by previous repair cooldown: %q", address)
		}
		if !strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
			t.Fatal("changed PPP binding did not restart Samba")
		}
	}
	// With unchanged bindings, retain the restart throttle while smbd starts.
	r.calls = nil
	if err := s.ReconcileVPNListeners(ctx, c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
		t.Fatal("unchanged listener repair bypassed startup cooldown")
	}
}

func TestBoundL2TPListenerSurvivesDisconnectAndReconnect(t *testing.T) {
	r := &vpnAddressRunner{fakeRunner: newRunner()}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	c := fixture()
	c.Samba.VPNs = []string{"l2tp"}
	c.VPNServers = []config.VPNServer{{ID: "l2tp", Index: 30, Enabled: true, Type: "l2tp", Subnet: "10.99.1.1/24"}}
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	r.address = "17: pp30-0a630102 inet 10.99.1.1 peer 10.99.1.2/32 scope global pp30-0a630102\n"
	if err := s.ReconcileVPNListeners(ctx, c); err != nil {
		t.Fatal(err)
	}
	r.listeners += "LISTEN 0 50 10.99.1.1:445 0.0.0.0:*\n"
	for _, address := range []string{"", r.address, "", r.address} {
		r.address = address
		r.calls = nil
		if err := s.ReconcileVPNListeners(ctx, c); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(r.calls, "\n"), "systemctl restart netos-samba.service") {
			t.Fatal("healthy, selected listener restarted on PPP state change")
		}
	}
	// Selection changes must still close the listener, even when PPP is down.
	c.Samba.VPNs = nil
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(s.StateDir, "samba.conf"))
	if err != nil || strings.Contains(string(conf), "10.99.1.1/24") {
		t.Fatal("revoked VPN binding retained")
	}
}

func TestAccessesLANSelection(t *testing.T) {
	c := fixture()
	c.Interfaces = append(c.Interfaces, config.Interface{ID: "lanif", Name: "later"})
	c.Samba.Networks = []string{"other", "lan", "lan", "disabled", "bad"}
	c.Networks = append(c.Networks,
		config.Network{ID: "other", Interface: "missing", Enabled: true, RouterAddress: "10.0.0.1/24"},
		config.Network{ID: "disabled", RouterAddress: "10.1.1.1/32"},
		config.Network{ID: "bad", Enabled: true, RouterAddress: "bad"},
		c.Networks[0],
	)
	want := []Access{
		{Interface: "eth1", Subnet: "192.168.50.0/24"},
		{Subnet: "10.0.0.0/24"},
		{Interface: "eth1", Subnet: "192.168.50.0/24"},
	}
	if got := Accesses(c); !slices.Equal(got, want) {
		t.Fatalf("accesses = %v, want %v", got, want)
	}
	c.Samba.Networks = []string{"lan"}
	c.Interfaces[0].Name = "renamed"
	want = []Access{{Interface: "renamed", Subnet: "192.168.50.0/24"}, {Interface: "renamed", Subnet: "192.168.50.0/24"}}
	if got := Accesses(c); !slices.Equal(got, want) {
		t.Fatalf("after edit = %v, want %v", got, want)
	}
	c.Samba.Networks = nil
	if got := Accesses(c); got != nil {
		t.Fatal(got)
	}
}

func BenchmarkRenderSelectedLANs(b *testing.B) {
	for _, n := range []int{32, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := config.Default()
			for i := 0; i < n; i++ {
				id := fmt.Sprintf("net%d", i)
				iface := fmt.Sprintf("eth%d", i)
				c.Interfaces = append(c.Interfaces, config.Interface{ID: iface, Name: iface})
				c.Networks = append(c.Networks, config.Network{ID: id, Interface: iface, Enabled: true, RouterAddress: fmt.Sprintf("10.%d.%d.1/24", i/256, i%256)})
				c.Samba.Networks = append(c.Samba.Networks, id)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Render(c, "generated"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestRenderShareVolumeSelection(t *testing.T) {
	c := config.Default()
	c.Samba.Volumes = []config.StorageVolume{
		{ID: "disk", Enabled: true, UUID: "first"},
		{ID: "disk", Enabled: true, UUID: "last"},
		{ID: "disk", UUID: "disabled"},
	}
	c.Samba.Shares = []config.SambaShare{{Name: "skip"}, {Name: "share", Volume: "disk", Enabled: true}}
	for _, want := range []string{"last", "first"} {
		out, err := Render(c, "generated")
		if err != nil || !strings.Contains(out, MountPath(c.Samba.Volumes[0])+" "+want+"\n") {
			t.Fatalf("expected selected volume %q: %v", want, err)
		}
		c.Samba.Volumes[1].Enabled = false
	}
	c.Samba.Volumes[0].Enabled = false
	if _, err := Render(c, "generated"); err == nil || err.Error() != "share share: volume unavailable" {
		t.Fatal(err)
	}
}

func BenchmarkRenderShareVolumes(b *testing.B) {
	for _, n := range []int{32, 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := config.Default()
			for i := 0; i < n; i++ {
				id := fmt.Sprint(i)
				c.Samba.Volumes = append(c.Samba.Volumes, config.StorageVolume{ID: id, Enabled: true})
				c.Samba.Shares = append(c.Samba.Shares, config.SambaShare{Name: "share" + id, Volume: id, Enabled: true})
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Render(c, "generated"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestDiscoverySelectionTracksInterfaceEdits(t *testing.T) {
	c := config.Default()
	c.Samba.Networks = []string{"b", "a", "a", "disabled", "duplicate", "unresolved"}
	c.Interfaces = []config.Interface{{ID: "one", Name: "eth1"}, {ID: "one", Name: "ignored"}, {ID: "two", Name: "eth2"}}
	c.Networks = []config.Network{
		{ID: "a", Interface: "one", Enabled: true}, {ID: "disabled", Interface: "two"},
		{ID: "duplicate", Interface: "one", Enabled: true}, {ID: "b", Interface: "two", Enabled: true},
		{ID: "unresolved", Interface: "absent", Enabled: true},
	}
	check := func(want []string) {
		t.Helper()
		var got []string
		for _, command := range strings.Split(discoveryUnit(c), "/usr/sbin/wsdd2 -4 -w -i ")[1:] {
			name, _, ok := strings.Cut(command, " -H ")
			if !ok {
				t.Fatal(command)
			}
			got = append(got, name)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("discovery interfaces %q, want %q", got, want)
		}
	}
	check([]string{"eth1", "eth2", ""})
	c.Interfaces[0].Name = "renamed"
	c.Networks[3].Enabled = false
	check([]string{"renamed", ""})
	c.Samba.Networks = nil
	check(nil)
}

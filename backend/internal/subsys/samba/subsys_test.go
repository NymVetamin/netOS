package samba

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type fakeRunner struct {
	active, enabled map[string]bool
	calls           []string
	devices, fail   string
	listeners       string
}

func newRunner() *fakeRunner {
	return &fakeRunner{active: map[string]bool{}, enabled: map[string]bool{}, devices: `{"blockdevices":[]}`, listeners: "LISTEN 0 50 192.168.50.1:445 0.0.0.0:*\n"}
}
func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	if r.fail != "" && strings.Contains(cmd, r.fail) {
		return "", fmt.Errorf("injected failure: %s", cmd)
	}
	switch name {
	case "ss":
		return r.listeners, nil
	case "lsblk":
		return r.devices, nil
	case "getent":
		return args[1] + ":x:991:993:netOS Samba:/nonexistent:/usr/sbin/nologin\n", nil
	case "id":
		return "993\n", nil
	case "systemctl":
		unit := args[len(args)-1]
		switch args[0] {
		case "is-active":
			if r.active[unit] {
				return "active", nil
			}
			return "inactive", fmt.Errorf("inactive")
		case "is-enabled":
			if r.enabled[unit] {
				return "enabled", nil
			}
			return "disabled", fmt.Errorf("disabled")
		case "enable":
			r.enabled[unit] = true
		case "disable":
			r.enabled[unit] = false
		case "start", "restart":
			r.active[unit] = true
			if unit == "netos-samba.service" {
				r.listeners = "LISTEN 0 50 192.168.50.1:445 0.0.0.0:*\n"
			}
		case "stop":
			r.active[unit] = false
		}
	}
	return "", nil
}
func (r *fakeRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}
func fixture() *config.Config {
	c := config.Default()
	c.Components = append(c.Components, config.Component{ID: "samba", Installed: true})
	c.Interfaces = []config.Interface{{ID: "lanif", Name: "eth1", Type: "physical", Enabled: true}}
	c.Networks = []config.Network{{ID: "lan", Name: "LAN", Interface: "lanif", Enabled: true, RouterAddress: "192.168.50.1/24", Zone: "lan"}}
	c.Samba = config.Samba{Enabled: true, Discovery: true, Networks: []string{"lan"}, Volumes: []config.StorageVolume{{ID: "usb", UUID: "ABCD-1234", Filesystem: "exfat", Enabled: true}}, Users: []config.SambaUser{{ID: "alice", Name: "alice", Password: "Secret123"}}, Shares: []config.SambaShare{{ID: "files", Name: "Files", Volume: "usb", Enabled: true, ReadOnly: true, Users: []string{"alice"}}}}
	return c
}
func testSubsystem(t *testing.T, r *fakeRunner) *Subsystem {
	t.Helper()
	s := New(r, filepath.Join(t.TempDir(), "generated"))
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	return s
}
func TestApplyIdempotentAndLifecycle(t *testing.T) {
	r := newRunner()
	s := testSubsystem(t, r)
	c := fixture()
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(s.StateDir, "samba", "smbpasswd"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "Secret123") || !strings.Contains(string(data), ntHash("Secret123")) {
		t.Fatal("password file must contain only NT hashes")
	}
	if strings.Contains(string(data), "LCT-00000000") || !strings.Contains(string(data), "[UX         ]") {
		t.Fatal("password must not require an unsupported password-change login")
	}
	text, _ := os.ReadFile(filepath.Join(s.UnitDir, mountUnit(c.Samba.Volumes[0])))
	if !strings.Contains(string(text), "uid=991,gid=993") {
		t.Fatalf("UID/GID confused: %s", text)
	}
	r.calls = nil
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range r.calls {
		if strings.Contains(cmd, "systemctl restart") || strings.Contains(cmd, "systemctl stop") {
			t.Fatalf("idempotent apply interrupts SMB: %s", cmd)
		}
	}
	if plan, err := s.Plan(c, c); err != nil || len(plan) != 0 {
		t.Fatalf("no drift expected: %v %v", plan, err)
	}
	// A password change revokes old sessions before the new credentials load.
	c.Samba.Users[0].Password = "Changed123"
	r.calls = nil
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(r.calls, "\n")
	if !strings.Contains(calls, "systemctl stop netos-samba.service") {
		t.Fatal("old sessions were not revoked")
	}
	c.Samba.Enabled = false
	c.Samba.Volumes[0].Enabled = false
	c.Samba.Shares[0].Enabled = false
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if r.active["netos-samba.service"] || r.active["netos-wsdd.service"] {
		t.Fatal("disabled service remains running")
	}
	if _, err := os.Stat(filepath.Join(s.UnitDir, mountUnit(c.Samba.Volumes[0]))); !os.IsNotExist(err) {
		t.Fatal("mount unit remains")
	}
	if _, err := os.Stat(filepath.Join(s.StateDir, "samba", "smbpasswd")); !os.IsNotExist(err) {
		t.Fatal("credentials remain published")
	}
}
func TestBusyUnmountFailsAndRollbackRecovers(t *testing.T) {
	r := newRunner()
	s := testSubsystem(t, r)
	c := fixture()
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	mount := mountUnit(c.Samba.Volumes[0])
	r.active[mount] = true
	r.fail = "systemctl stop " + mount
	c.Samba.Volumes[0].Enabled = false
	c.Samba.Shares[0].Enabled = false
	if err := s.Apply(ctx, c); err == nil {
		t.Fatal("busy mount reported ejected")
	}
	r.fail = ""
	c.Samba.Volumes[0].Enabled = true
	c.Samba.Shares[0].Enabled = true
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if !r.active["netos-samba.service"] {
		t.Fatal("rollback did not restore Samba")
	}
	for _, cmd := range r.calls {
		if strings.Contains(cmd, "umount -l") || strings.Contains(cmd, "umount -f") {
			t.Fatal("forced unmount")
		}
	}
}
func TestRefusesSystemDisksAndForeignUnitsBeforeMutation(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			r := newRunner()
			s := testSubsystem(t, r)
			c := fixture()
			if foreign {
				_ = os.MkdirAll(s.UnitDir, 0755)
				_ = os.WriteFile(filepath.Join(s.UnitDir, mountUnit(c.Samba.Volumes[0])), []byte("foreign"), 0644)
			} else {
				r.devices = `{"blockdevices":[{"path":"/dev/sda1","uuid":"ABCD-1234","fstype":"exfat","type":"part","mountpoints":["/"]}]}`
			}
			if err := s.Apply(context.Background(), c); err == nil {
				t.Fatal("unsafe volume accepted")
			}
			for _, cmd := range r.calls {
				if strings.HasPrefix(cmd, "systemctl ") || strings.HasPrefix(cmd, "useradd ") {
					t.Fatalf("mutation before preflight: %s", cmd)
				}
			}
		})
	}
}
func TestFailedConfigCheckDoesNotStartSMBAndCanRollBack(t *testing.T) {
	r := newRunner()
	r.fail = "testparm"
	s := testSubsystem(t, r)
	c := fixture()
	if err := s.Apply(context.Background(), c); err == nil {
		t.Fatal("invalid generated config accepted")
	}
	if r.active["netos-samba.service"] {
		t.Fatal("Samba started before config validation")
	}
	r.fail = ""
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	for unit, active := range r.active {
		if active {
			t.Fatalf("orphan unit %s", unit)
		}
	}
}
func TestNTHashAndRenderSecurity(t *testing.T) {
	if got := ntHash("password"); got != "8846F7EAEE8FB117AD06BDD830B7586C" {
		t.Fatalf("NT hash: %s", got)
	}
	c := fixture()
	conf, err := Render(c, "/var/lib/netos/generated")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server min protocol = SMB2_02", "smb ports = 445", "hosts deny = ALL", "guest ok = no", "follow symlinks = no", "read only = yes", "root preexec close = yes", `"eth1;options=dynamic"`, "ABCD-1234"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(conf, "Secret123") {
		t.Fatal("render leaks password")
	}
	if strings.Contains(discoveryUnit(c), " -i lo") || !strings.Contains(discoveryUnit(c), " -i eth1") {
		t.Fatal("discovery interfaces")
	}
	if !strings.Contains(mountGuard, "-o UUID") {
		t.Fatal("fallback directory not guarded")
	}
}

func TestPlanRepairsArtifactDrift(t *testing.T) {
	r := newRunner()
	s := testSubsystem(t, r)
	c := fixture()
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(s.StateDir, "samba.conf"), filepath.Join(s.StateDir, "samba", "smbpasswd"), filepath.Join(s.StateDir, "samba", "users.map"), filepath.Join(s.UnitDir, "netos-samba.service"), filepath.Join(s.UnitDir, mountUnit(c.Samba.Volumes[0]))} {
		if err := os.WriteFile(path, []byte("drift"), 0600); err != nil {
			t.Fatal(err)
		}
		if plan, err := s.Plan(c, c); err != nil || len(plan) == 0 {
			t.Fatalf("drift missing for %s: %v", path, err)
		}
		if err := s.Apply(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
}
func TestDeviceDiscoveryNestedAndDuplicateUUID(t *testing.T) {
	data := `{"blockdevices":[{"path":"/dev/sda","tran":"usb","children":[{"path":"/dev/sda1","uuid":"ABCD-1234","fstype":"exfat","type":"part","size":12345,"mountpoints":[null]}]},{"path":"/dev/sdb1","uuid":"AAAA-BBBB","fstype":"ext4","type":"part","mountpoints":["/"]}]}`
	d, err := ParseDevices([]byte(data))
	if err != nil || len(d) != 2 {
		t.Fatalf("%v %v", d, err)
	}
	if !d[0].Available || d[0].Transport != "usb" || d[1].Available {
		t.Fatalf("unexpected devices: %#v", d)
	}
	data = strings.Replace(data, "AAAA-BBBB", "abcd-1234", 1)
	d, err = ParseDevices([]byte(data))
	if err != nil || d[0].Available || d[1].Available {
		t.Fatal("duplicate filesystem UUID accepted")
	}
}

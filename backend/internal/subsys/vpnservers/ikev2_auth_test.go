package vpnservers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIKEv2NTPasswordKnownVectors(t *testing.T) {
	for password, want := range map[string]string{
		"":         "31d6cfe0d16ae931b73c59d7e0c089c0",
		"password": "8846f7eaee8fb117ad06bdd830b7586c",
		"Password": "a4f49c406510bdcab6824ee7c30fd852",
	} {
		if got := ikev2NTPassword(password); got != want {
			t.Fatalf("NT hash mismatch: %s", got)
		}
	}
}

func TestIKEv2AuthDoesNotInterpolatePasswordsOrIncludeDisabledPeers(t *testing.T) {
	_, server := ikev2TestConfig()
	server.Peers[0].Credentials["password"] = "secret\"\\%{exec:bad}$Привет😀"
	server.Config["dns"] = []string{"10.40.0.1", "1.1.1.1", "9.9.9.9"}
	server.Peers = append(server.Peers, config.VPNPeer{Enabled: false, Address: "10.40.0.3", Credentials: map[string]string{"username": "disabled"}})
	b, err := renderIKEv2AuthUsers([]config.VPNServer{server})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", "%{", "exec:", "disabled", "10.40.0.3"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("unexpected interpolation/disabled account: %s", b)
		}
	}
	for _, dns := range []string{"10.40.0.1", "1.1.1.1", "9.9.9.9"} {
		if !strings.Contains(string(b), " += "+dns) {
			t.Fatalf("DNS lost: %s", dns)
		}
	}
}

func TestIKEv2AuthCheckFailurePreservesRunningServicesAndFiles(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	r := &vpnServiceRunner{active: map[string]bool{}, s: s}
	s.Runner = r
	cfg, server := ikev2TestConfig()
	ctx := context.Background()
	if err := s.applyIKEv2(ctx, cfg, []config.VPNServer{server}, false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.ikev2Paths().authRoot, "users")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	r.failOn = "/usr/sbin/freeradius -C"
	server.Peers[0].Credentials["password"] = "changed-secret"
	if err := s.applyIKEv2(ctx, cfg, []config.VPNServer{server}, true); err == nil {
		t.Fatal("invalid auth config accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("auth files not restored")
	}
	for _, command := range r.commands {
		if strings.Contains(command, "systemctl restart") || strings.Contains(command, "systemctl stop") {
			t.Fatalf("validation failure interrupted running service: %s", command)
		}
	}
	if !r.active[ikev2Unit] || !r.active[ikev2AuthUnit] {
		t.Fatal("service stopped")
	}
}

func TestIKEv2AuthOrphanUnitIsCleaned(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = t.TempDir()
	r := &vpnServiceRunner{active: map[string]bool{ikev2AuthUnit: true}, s: s}
	s.Runner = r
	if err := os.WriteFile(s.ikev2Paths().authUnit, []byte("owned fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.cleanupIKEv2(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.ikev2Paths().authUnit); !os.IsNotExist(err) {
		t.Fatal("auth unit left behind")
	}
	if r.active[ikev2AuthUnit] {
		t.Fatal("auth service left running")
	}
}

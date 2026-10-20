package channels

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestChannelArmorPreservesServerAndAdminRules(t *testing.T) {
	s, _ := newTestSubsystem(t)
	for _, profile := range channelArmorFiles {
		if err := os.MkdirAll(filepath.Join(s.AppArmorDir, "local"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(s.AppArmorDir, profile), []byte("#include <local/"+profile+">\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(s.AppArmorDir, "local", channelArmorFiles[0])
	original := "# admin\n/custom r,\n# BEGIN netOS IKEv2\n/server/** r,\n# END netOS IKEv2\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.AppArmorProfiles, []byte("/usr/sbin/swanctl (enforce)\n/usr/sbin/charon-systemd (enforce)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func(context.Context, string, ...string) (string, error) {
		calls++
		if calls == 1 {
			return "", errors.New("reload failed")
		}
		return "", nil
	}
	if err := syncChannelArmor(context.Background(), s.AppArmorDir, s.AppArmorProfiles, s.StateDir, true, run); err == nil {
		t.Fatal("reload failure hidden")
	}
	for i := 0; i < 2; i++ {
		if err := syncChannelArmor(context.Background(), s.AppArmorDir, s.AppArmorProfiles, s.StateDir, true, run); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), original) || strings.Count(string(data), channelArmorBegin) != 1 {
		t.Fatal("existing policy overwritten or duplicate rules")
	}
	for _, want := range []string{"/swanctl.conf", "/x509ca/", "/x509ca/ca.crt", "/strongswan.conf", "/run/netos-ikev2-ch[0-9]*/charon.vici"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(strings.TrimPrefix(string(data), original), "/**") {
		t.Fatal("unexpected recursive grant")
	}
	if err := RemoveIKEv2ChannelAppArmor(context.Background(), s.AppArmorDir, s.AppArmorProfiles, run); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != original {
		t.Fatal("server/admin rules not preserved")
	}
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("file mode changed")
	}
	if _, err := os.Stat(filepath.Join(s.AppArmorDir, "local", channelArmorFiles[1])); err != nil {
		t.Fatal("mandatory local include deleted")
	}
	if calls != 7 {
		t.Fatalf("reloads %d", calls)
	}
}

func TestChannelArmorFailurePrecedesNetworkChanges(t *testing.T) {
	s, r := newTestSubsystem(t)
	if err := os.MkdirAll(s.AppArmorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.AppArmorDir, channelArmorFiles[0]), []byte("# no local include"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := channelConfig()
	cfg.Channels[1].Type = "ikev2"
	cfg.Channels[1].Config = map[string]any{"server": "192.0.2.2", "server_identity": "test", "username": "test", "password": "test"}
	if err := s.Apply(context.Background(), cfg); err == nil {
		t.Fatal("missing include accepted")
	}
	for _, cmd := range r.commands {
		if !strings.HasPrefix(cmd, "apparmor_parser ") {
			t.Fatalf("network/service touched before profile check: %s", cmd)
		}
	}
}

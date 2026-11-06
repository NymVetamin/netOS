package channels

import (
	"context"
	"encoding/base64"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestOpenConnectCertificateLifecycle(t *testing.T) {
	s, _ := newTestSubsystem(t)
	runner := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
	s.Runner = runner
	ch := serviceTestChannel("openconnect")
	ch.Config["auth_mode"] = "certificate"
	ch.Config["client_certificate"] = base64.StdEncoding.EncodeToString([]byte("original-p12"))
	ch.Config["certificate_password"] = "p12-password"
	if _, err := s.applyOpenConnect(context.Background(), ch, false, true); err != nil {
		t.Fatal(err)
	}
	conf, _, script, unit := s.openConnectPaths(ch)
	cert := openConnectCertificatePath(script)
	info, err := os.Stat(cert)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("certificate permissions", err)
	}
	unitData, _ := os.ReadFile(unit)
	if strings.Contains(string(unitData), "p12-password") {
		t.Fatal("secret in argv/unit")
	}
	before, _ := os.ReadFile(conf)
	removed, err := s.captureRemovedChannel(context.Background(), ownedChannel{Index: ch.Index, Type: ch.Type})
	if err != nil {
		t.Fatal(err)
	}
	s.cleanupOpenConnect(context.Background(), ch)
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		t.Fatal("cleanup left certificate")
	}
	if err := restoreChannelFiles(removed.files); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(cert)
	if string(restored) != "original-p12" {
		t.Fatal("removed-channel snapshot lost certificate")
	}
	runner.failOnce = "systemctl restart"
	runner.failed = false
	ch.Config["client_certificate"] = base64.StdEncoding.EncodeToString([]byte("replacement-p12"))
	if _, err := s.applyOpenConnect(context.Background(), ch, true, true); err == nil {
		t.Fatal("injected restart failure accepted")
	}
	restored, _ = os.ReadFile(cert)
	after, _ := os.ReadFile(conf)
	if string(restored) != "original-p12" || string(before) != string(after) {
		t.Fatal("rollback lost credential")
	}
	if _, err := s.applyOpenConnect(context.Background(), ch, true, true); err != nil {
		t.Fatal("retry", err)
	}
	ch.Config["auth_mode"] = "password"
	if _, err := s.applyOpenConnect(context.Background(), ch, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		t.Fatal("password mode retained certificate file")
	}
	start := len(runner.commands)
	if _, err := s.applyOpenConnect(context.Background(), ch, true, true); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range runner.commands[start:] {
		if strings.Contains(cmd, "systemctl restart") {
			t.Fatal("password-mode repeat restarted")
		}
	}
}

package certificates

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestVPNPublicExportPreservesAndRepairs(t *testing.T) {
	issuer := makeIssuer(t, "router.example.test")
	m := New(t.TempDir(), func(_, _, _ string) (ACME, error) { return issuer, nil })
	m.HTTPAddress = "127.0.0.1:0"
	defer m.Close()
	cfg := config.Default()
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "router.example.test"}
	server := config.VPNServer{ID: "vpn", Type: "ocserv", Config: map[string]any{"public_endpoint": "router.example.test:443", "tls": map[string]any{"mode": "panel"}}}
	dir := t.TempDir()
	file := filepath.Join(dir, "panel.crt")
	if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || !changed {
		t.Fatal(changed, err)
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(want, []byte("PRIVATE KEY")) {
		t.Fatal("public export contains private key")
	}
	stamp := time.Unix(1234567890, 0)
	if err := os.Chtimes(file, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || changed {
			t.Fatal(changed, err)
		}
		after, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
			t.Fatal("unchanged public certificate rewritten")
		}
	}
	mutations := []func() error{
		func() error { return os.Remove(file) },
		func() error { return os.WriteFile(file, []byte("corrupt"), 0644) },
	}
	if runtime.GOOS != "windows" {
		mutations = append(mutations, func() error { return os.Chmod(file, 0600) }, func() error {
			other := filepath.Join(dir, "other.crt")
			if err := os.WriteFile(other, want, 0644); err != nil {
				return err
			}
			if err := os.Remove(file); err != nil {
				return err
			}
			return os.Symlink(other, file)
		})
	}
	for _, mutate := range mutations {
		if err := mutate(); err != nil {
			t.Fatal(err)
		}
		if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || changed {
			t.Fatal("public repair changed private bundle", changed, err)
		}
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("export not repaired", err)
		}
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("not regular", err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0644 {
			t.Fatal(info.Mode())
		}
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(file, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.VPN(context.Background(), cfg, server, dir); err == nil {
		t.Fatal("write error hidden")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || changed {
		t.Fatal("retry failed", changed, err)
	}
	issuer.cert = makeIssuer(t, "router.example.test").cert
	if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || !changed {
		t.Fatal("renewal failed", changed, err)
	}
	renewed, err := os.ReadFile(file)
	if err != nil || bytes.Equal(renewed, want) {
		t.Fatal("renewal not exported", err)
	}
}

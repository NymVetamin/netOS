package vpnservers

import (
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
)

func ocservIntegrityFixture(t testing.TB, n, routes int, mode string) (string, string, config.VPNServer) {
	t.Helper()
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	if err := os.Mkdir(users, 0700); err != nil {
		t.Fatal(err)
	}
	s := config.VPNServer{ID: "server", Type: "ocserv", Enabled: true, Config: map[string]any{"auth_mode": mode}}
	rs := []string{}
	for i := 0; i < routes; i++ {
		rs = append(rs, fmt.Sprintf("10.%d.0.0/16", i%256))
	}
	s.Config["routes"] = rs
	var passwd strings.Builder
	for i := 0; i < n; i++ {
		p := config.VPNPeer{ID: fmt.Sprintf("peer%d", i), Enabled: true, Address: fmt.Sprintf("10.1.%d.%d", i/250, i%250+2), Credentials: map[string]string{"username": fmt.Sprintf("user%d", i), "password": "test-password"}}
		s.Peers = append(s.Peers, p)
		name := s.OcservUsername(p)
		if mode != "certificate" {
			fmt.Fprintf(&passwd, "%s:group:hash\n", name)
		}
		if err := os.WriteFile(filepath.Join(users, name), []byte("explicit-ipv4 = "+p.Address+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "passwd")
	if err := os.WriteFile(path, []byte(passwd.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return path, users, s
}
func TestOcservStateIntegrityAndRecovery(t *testing.T) {
	for _, mode := range []string{"", "password", "certificate", "certificate_password"} {
		t.Run(mode, func(t *testing.T) {
			p, u, s := ocservIntegrityFixture(t, 3, 10, mode)
			var good *ocservAuthState
			check := func(wantOK bool) {
				t.Helper()
				state, err := ocservStateFor(p, u, s)
				if (err == nil) != wantOK {
					t.Fatalf("expected healthy=%v, got %v", wantOK, err)
				}
				if err == nil {
					if good != nil && state != *good {
						t.Fatal("recovery changed authentication fingerprint")
					}
					saved := state
					good = &saved
				}
			}
			check(true)
			file := filepath.Join(u, s.OcservUsername(s.Peers[0]))
			original, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(file, []byte("wrong-address\n"), 0600); err != nil {
				t.Fatal(err)
			}
			check(false)
			if err = os.WriteFile(file, original, 0600); err != nil {
				t.Fatal(err)
			}
			check(true)
			if goruntime.GOOS != "windows" {
				if err = os.Chmod(file, 0644); err != nil {
					t.Fatal(err)
				}
				check(false)
				if err = os.Chmod(file, 0600); err != nil {
					t.Fatal(err)
				}
				check(true)
				if err = os.Rename(file, filepath.Join(filepath.Dir(u), "saved")); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(filepath.Join(filepath.Dir(u), "saved"), file); err != nil {
					t.Fatal(err)
				}
				check(false)
				os.Remove(file)
				os.Rename(filepath.Join(filepath.Dir(u), "saved"), file)
				check(true)
			}
			s.Peers[0].Enabled = false
			check(false)
			s.Peers[0].Enabled = true
			check(true)
			os.Remove(file)
			check(false)
			if err = os.WriteFile(file, original, 0600); err != nil {
				t.Fatal(err)
			}
			check(true)
		})
	}
}

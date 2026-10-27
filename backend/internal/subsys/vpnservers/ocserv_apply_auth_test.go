package vpnservers

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOcservApplyAuthenticationModesAndRetry(t *testing.T) {
	for _, mode := range []string{"", "password", "certificate", "certificate_password", "unknown"} {
		t.Run("mode="+mode, func(t *testing.T) {
			s, _ := newTestSubsystem(t)
			s.UnitDir = t.TempDir()
			runner := &vpnServiceRunner{active: map[string]bool{}}
			s.Runner = runner
			cfg, server := ocservConfig()
			server.Config["auth_mode"] = mode
			server.Peers = append(server.Peers, config.VPNPeer{ID: "second", Enabled: true, Address: "10.30.0.3", Credentials: map[string]string{"username": "second-name", "password": "second-password"}}, config.VPNPeer{ID: "disabled", Enabled: false, Address: "10.30.0.4", Credentials: map[string]string{"username": "disabled", "password": "disabled-password"}})
			apply := func() error {
				cfg.VPNServers = []config.VPNServer{server}
				_, err := s.applyOcserv(context.Background(), cfg, server, true)
				return err
			}
			if err := apply(); err != nil {
				t.Fatal(err)
			}
			paths := s.ocservPaths(server)
			check := func() {
				t.Helper()
				entries, err := os.ReadDir(paths.users)
				if err != nil || len(entries) != 2 {
					t.Fatalf("users=%v err=%v", entries, err)
				}
				for _, peer := range server.Peers[:2] {
					name := peer.Credentials["username"]
					if server.Config["auth_mode"] != "" && server.Config["auth_mode"] != "password" {
						name = "netos-" + peer.ID
					}
					data, err := os.ReadFile(filepath.Join(paths.users, name))
					if err != nil || string(data) != fmt.Sprintf("explicit-ipv4 = %s\n", peer.Address) {
						t.Fatalf("user %s: %q %v", name, data, err)
					}
				}
				if err := ocservAuthHealth(paths, server); err != nil {
					t.Fatal(err)
				}
			}
			check()
			wantCalls := 2
			if mode == "certificate" {
				wantCalls = 0
			}
			if got := strings.Count(strings.Join(runner.commands, "\n"), "ocpasswd "); got != wantCalls {
				t.Fatalf("password calls=%d want=%d", got, wantCalls)
			}
			runner.commands = nil
			if err := apply(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.Join(runner.commands, "\n"), "ocpasswd ") {
				t.Fatal("unchanged apply regenerated passwords")
			}
			// Changing the mode must use the new configuration, not the previous apply.
			server.Config["auth_mode"] = "password"
			if mode == "password" || mode == "" {
				server.Config["auth_mode"] = "certificate_password"
			}
			before, err := os.ReadFile(paths.passwd)
			if err != nil {
				t.Fatal(err)
			}
			runner.failOn, runner.failAt, runner.failSeen = "ocpasswd ", 1, 0
			if err := apply(); err == nil {
				t.Fatal("password failure was ignored")
			}
			after, err := os.ReadFile(paths.passwd)
			if err != nil || string(before) != string(after) {
				t.Fatal("failed update changed live password file")
			}
			runner.failOn = ""
			if err := apply(); err != nil {
				t.Fatal(err)
			}
			check()
			if err := apply(); err != nil {
				t.Fatal(err)
			}
			check()
		})
	}
}

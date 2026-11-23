package hostsettings

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestNTPResetRetriesFailedRestart(t *testing.T) {
	base := &hostRunner{ntpServers: "192.0.2.99 192.0.2.10"}
	runner := &failingHostRunner{base: base, fail: "systemctl restart systemd-timesyncd.service"}
	s := New(runner)
	s.TimesyncdPath = filepath.Join(t.TempDir(), "90-netos.conf")
	cfg := config.Default()
	cfg.System.NTP.Servers = []string{"192.0.2.10"}
	ctx := context.Background()
	if err := s.applyNTP(ctx, cfg); err == nil {
		t.Fatal("restart failure hidden")
	}
	runner.fail = ""
	base.commands = nil
	if err := s.applyNTP(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if !hasCommand(base.commands, "systemctl restart systemd-timesyncd.service") {
		t.Fatal("unchanged file prevented recovery")
	}
	base.ntpServers = "192.0.2.10"
	base.commands = nil
	if err := s.applyNTP(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if hasCommand(base.commands, "systemctl restart systemd-timesyncd.service") {
		t.Fatal("healthy repeat restarted daemon")
	}
}

func TestNTPReplacesEarlierServers(t *testing.T) {
	for _, servers := range [][]string{nil, {"192.0.2.10"}, {"192.0.2.11", "192.0.2.10"}} {
		cfg := config.Default()
		cfg.System.NTP.Servers = servers
		for range 2 {
			// timesyncd.conf: repeated assignments append; an empty one resets.
			got := []string{"192.0.2.99"}
			for _, line := range strings.Split(string(New(nil).renderNTP(cfg)), "\n") {
				if value, ok := strings.CutPrefix(line, "NTP="); ok {
					if value == "" {
						got = nil
					} else {
						got = append(got, strings.Fields(value)...)
					}
				}
			}
			if !slices.Equal(got, servers) {
				t.Fatalf("servers=%v want=%v", got, servers)
			}
		}
	}
}

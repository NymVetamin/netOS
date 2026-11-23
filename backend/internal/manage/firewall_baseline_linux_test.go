package manage

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestIntegrationRestorePartialFirewallSnapshot(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root in an isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	init, initErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initErr != nil || self == init {
		t.Fatal("requires an isolated network namespace")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %s: %v", name, args, out, err)
		}
		return string(out)
	}
	b := &systemBaseline{IPTables6Exists: true}
	for _, tool := range []string{"iptables", "ip6tables"} {
		run(tool, "-N", "ORIGINAL")
		run(tool, "-A", "ORIGINAL", "-j", "RETURN")
		snapshot := run(tool+"-save", "-t", "filter")
		if tool == "iptables" {
			b.IPTables4 = snapshot
		} else {
			b.IPTables6 = snapshot
		}
		for _, table := range []string{"filter", "nat", "mangle", "raw"} {
			run(tool, "-t", table, "-N", "AFTER_INSTALL")
			run(tool, "-t", table, "-A", "AFTER_INSTALL", "-j", "RETURN")
		}
	}
	m := New("test")
	for attempt := 0; attempt < 2; attempt++ {
		if err := m.restoreBaselineFirewall(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		for _, tool := range []string{"iptables", "ip6tables"} {
			for _, table := range []string{"filter", "nat", "mangle", "raw"} {
				out := run(tool+"-save", "-t", table)
				foreign := table == "raw" || (table == "nat" && tool == "ip6tables")
				if strings.Contains(out, "AFTER_INSTALL") != foreign {
					t.Errorf("restore %d: %s %s: unexpected chain state", attempt, tool, table)
				}
				if table == "filter" && !strings.Contains(out, "-A ORIGINAL -j RETURN") {
					t.Fatalf("%s lost original rule", tool)
				}
			}
		}
	}
}

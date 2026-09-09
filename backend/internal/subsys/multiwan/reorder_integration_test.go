//go:build linux

package multiwan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type ownedNamespaceRunner struct{ name string }

func (r ownedNamespaceRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", r.name, name}, args...)...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, out)
	}
	return string(out), nil
}

func (r ownedNamespaceRunner) RunInput(ctx context.Context, input, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", r.name, name}, args...)...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestIntegrationReorderedWANsKeepTablesAndRemoveDeletedIndex(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	root := t.TempDir()
	ns := "qa-mw-" + filepath.Base(root) + fmt.Sprint(os.Getpid())
	// Creation must succeed before registering cleanup; never delete a namespace
	// belonging to another run in order to make room for this test.
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("create owned namespace: %v %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "del", ns).CombinedOutput(); err != nil {
			t.Errorf("remove owned namespace: %v %s", err, out)
		}
	})
	r := ownedNamespaceRunner{ns}
	ctx := context.Background()
	run := func(args ...string) string {
		t.Helper()
		out, err := r.Run(ctx, "ip", args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for i, name := range []string{"wan0", "wan1"} {
		run("link", "add", name, "type", "dummy")
		run("link", "set", name, "up")
		run("route", "add", "default", "dev", name, "metric", fmt.Sprint(100+i*100))
	}
	cfg := config.Default()
	cfg.MultiWAN.Enabled, cfg.MultiWAN.Mode = true, "balance"
	cfg.Interfaces = []config.Interface{{ID: "a", Name: "wan0"}, {ID: "b", Name: "wan1"}}
	cfg.WANs = []config.WAN{{ID: "first", Index: 7, Interface: "a", Enabled: true, Proto: "static", Weight: 1}, {ID: "second", Index: 19, Interface: "b", Enabled: true, Proto: "static", Weight: 3}}
	c := New(r, root, integrationLogger{t})
	apply := func() {
		t.Helper()
		if err := c.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	state := func() []string {
		return []string{run("route", "show", "table", "3007"), run("route", "show", "table", "3019"), run("rule", "show")}
	}
	apply()
	before := state()
	if !strings.Contains(before[0], "dev wan0") || !strings.Contains(before[1], "dev wan1") {
		t.Fatalf("wrong initial tables: %v", before)
	}
	cfg.WANs[0], cfg.WANs[1] = cfg.WANs[1], cfg.WANs[0]
	apply()
	if after := state(); !reflect.DeepEqual(before, after) {
		t.Fatalf("array permutation changed indexed routes/rules: before=%v after=%v", before, after)
	}
	t.Logf("reordered tables and rules unchanged: %v", before)
	cfg.WANs = cfg.WANs[:1] // Retain index 19, remove index 7.
	apply()
	routes, rules := run("route", "show", "table", "all"), run("rule", "show")
	if strings.Contains(routes, "table 3007") || strings.Contains(rules, "lookup 3007") || !strings.Contains(routes, "table 3019") || !strings.Contains(rules, "lookup 3019") {
		t.Fatalf("wrong deletion cleanup: %s\n%s", routes, rules)
	}
	cfg.MultiWAN.Enabled = false
	apply()
	routes, rules = run("route", "show", "table", "all"), run("rule", "show")
	if strings.Contains(routes, "table 3019") || strings.Contains(rules, "lookup 3019") {
		t.Fatalf("disabled balance retained state: %s\n%s", routes, rules)
	}
	t.Log("removed index 7 only, then disabled balance removed index 19; namespace cleanup registered")
}

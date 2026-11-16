package monitor

import (
	"context"
	"errors"
	"github.com/netos-router/netos/internal/config"
	"os/exec"
	"strings"
	"testing"
)

func TestAccountingDisabledAndReapply(t *testing.T) {
	c := &config.Config{}
	if Render(c, false) != "" {
		t.Fatal("disabled monitor added packet hooks")
	}
	c.TrafficMonitor.Enabled = true
	c.Interfaces = []config.Interface{{ID: "lan", Name: "br-lan", Enabled: true}}
	c.Networks = []config.Network{{Interface: "lan", RouterAddress: "192.0.2.1/24", Enabled: true}}
	first := Render(c, false)
	again := Render(c, true)
	if !strings.Contains(first, "hook forward priority 10") || !strings.Contains(first, "update @up4") || strings.Contains(first, " drop") {
		t.Fatal(first)
	}
	if strings.Contains(again, "delete table") || strings.Contains(again, "flush set") || strings.Contains(again, "add set") {
		t.Fatal("reapply resets counters")
	}
	c.TrafficMonitor.Enabled = false
	if !strings.Contains(Render(c, true), "delete table") {
		t.Fatal("disable leaves accounting hooks")
	}
}

func TestClearDoesNotHidePermissionFailure(t *testing.T) {
	denied := errors.New("Operation not permitted")
	if err := Clear(context.Background(), func(context.Context, string, ...string) (string, error) { return "", denied }); !errors.Is(err, denied) {
		t.Fatalf("hidden error: %v", err)
	}
	if err := Clear(context.Background(), func(context.Context, string, ...string) (string, error) { return "", exec.ErrNotFound }); err != nil {
		t.Fatal("missing nft is nothing to clear:", err)
	}
}

// Uninstall's runner reports a failed command as a bare "exit status 1" with
// stderr in its log: a missing table must be recognized without error text.
func TestClearDecidesByTableList(t *testing.T) {
	for _, tc := range []struct {
		name, tables, table string
		wantErr, deleted    bool
	}{
		{"absent", "table inet filter\ntable inet netos_traffic_monitor_old\n", "", false, false},
		{"owned", "table inet filter\ntable inet " + Table + "\n", "table inet " + Table + " { comment \"" + Owner + "\" }", false, true},
		{"foreign", "table inet " + Table + "\n", "table inet " + Table + " {}", true, false},
	} {
		var calls []string
		err := Clear(context.Background(), func(_ context.Context, _ string, args ...string) (string, error) {
			calls = append(calls, strings.Join(args, " "))
			switch strings.Join(args, " ") {
			case "list tables inet":
				return tc.tables, nil
			case "list table inet " + Table:
				return tc.table, nil
			case "delete table inet " + Table:
				return "", nil
			}
			return "", errors.New("exit status 1")
		})
		deleted := len(calls) > 0 && calls[len(calls)-1] == "delete table inet "+Table
		if (err != nil) != tc.wantErr || deleted != tc.deleted {
			t.Fatalf("%s: err=%v calls=%v", tc.name, err, calls)
		}
	}
}

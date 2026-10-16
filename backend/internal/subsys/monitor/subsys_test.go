package monitor

import (
	"context"
	"errors"
	"github.com/netos-router/netos/internal/config"
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
	c.Networks = []config.Network{{Interface: "lan", Enabled: true}}
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
	if err := Clear(context.Background(), func(context.Context, string, ...string) (string, error) {
		return "", errors.New("No such file or directory")
	}); err != nil {
		t.Fatal(err)
	}
}

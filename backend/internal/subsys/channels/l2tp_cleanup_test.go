package channels

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestRemovedL2TPChannelClearsItsFailedUnit(t *testing.T) {
	r := &channelRunner{}
	s := New(r, t.TempDir())
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	r.s = s
	s.cleanupL2TP(context.Background(), config.Channel{Index: 2})
	commands := strings.Join(r.commands, "\n")
	if !strings.Contains(commands, "systemctl daemon-reload\nsystemctl reset-failed netos-vpn-l2tp-ch2.service") {
		t.Fatalf("orphan failed state of removed L2TP channel: %s", commands)
	}
}

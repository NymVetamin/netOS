package vpnservers

import (
	"context"
	"errors"
	"testing"
)

type rejectExitGuard struct{ fakeRunner }

func (r *rejectExitGuard) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", errors.New("injected firewall failure")
}

func TestWireGuardExitDoesNotActivateWithoutProtection(t *testing.T) {
	cfg := serverConfig()
	server := cfg.VPNServers[0]
	server.Peers[0].UseAsChannel = true
	runner := &rejectExitGuard{}
	s := New(runner, t.TempDir())
	if _, err := s.applyWireGuard(context.Background(), server, false, true); err == nil {
		t.Fatal("accepted unprotected exit")
	}
	if len(runner.commands) != 0 {
		t.Fatal("changed interface after guard failure", runner.commands)
	}
}

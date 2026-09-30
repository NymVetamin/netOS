package vpnservers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestCleanupL2TPClearsOnlyRemovedUnitsFailedState(t *testing.T) {
	server := config.VPNServer{Index: 7}
	var commands []string
	runner := vpnRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return "", nil
	})
	s := New(runner, t.TempDir())
	s.UnitDir = t.TempDir()
	_, _, unitPath := s.l2tpPaths(server)
	if err := os.WriteFile(unitPath, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.cleanupL2TP(context.Background(), server)
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("removed unit still exists: %v", err)
	}
	want := "systemctl reset-failed " + filepath.Base(unitPath)
	if len(commands) == 0 || commands[len(commands)-1] != want {
		t.Fatalf("failed state not cleared after unit removal: %v", commands)
	}
}

func TestL2TPChapBlockPreservesOtherEntries(t *testing.T) {
	server := config.VPNServer{Index: 7, Peers: []config.VPNPeer{{Enabled: true, Address: "10.99.0.2", Credentials: map[string]string{"username": "alice", "password": "secret-one"}}}}
	original := []byte("# unrelated\nbob * pass *\n")
	added, err := updateL2TPChap(original, server, true)
	if err != nil || !strings.HasPrefix(string(added), string(original)) || !strings.Contains(string(added), "secret-one") {
		t.Fatalf("add block failed: %q, %v", added, err)
	}
	server.Peers[0].Credentials["password"] = "secret-two"
	updated, err := updateL2TPChap(added, server, true)
	if err != nil || strings.Contains(string(updated), "secret-one") || strings.Count(string(updated), "# BEGIN netos-l2tp-srv7") != 1 {
		t.Fatalf("update block failed: %q, %v", updated, err)
	}
	removed, err := updateL2TPChap(updated, server, false)
	if err != nil || string(removed) != string(original) {
		t.Fatalf("remove changed unrelated entries: %q, %v", removed, err)
	}
}

func TestL2TPChapBlockRejectsTruncatedBlock(t *testing.T) {
	server := config.VPNServer{Index: 7}
	if _, err := updateL2TPChap([]byte("# BEGIN netos-l2tp-srv7\n"), server, true); err == nil {
		t.Fatal("truncated managed credentials block accepted")
	}
}

package vpnservers

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

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

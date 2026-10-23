package vpnservers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestOcservChannelDoesNotChangeAuthentication(t *testing.T) {
	_, server := ocservConfig()
	root := t.TempDir()
	passwd, users := filepath.Join(root, "passwd"), filepath.Join(root, "users")
	if err := os.Mkdir(users, 0700); err != nil {
		t.Fatal(err)
	}
	username := server.OcservUsername(server.Peers[0])
	if err := os.WriteFile(passwd, []byte(username+":*:test-hash\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(users, username), []byte("explicit-ipv4 = "+server.Peers[0].Address+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := ocservStateFor(passwd, users, server)
	if err != nil {
		t.Fatal(err)
	}
	next := server
	next.Peers = append([]config.VPNPeer(nil), server.Peers...)
	next.DefaultChannel = "alternate"
	next.Peers[0].Channel = "alternate"
	after, err := ocservStateFor(passwd, users, next)
	if err != nil || before != after {
		t.Fatalf("routing changed authentication fingerprint: %v", err)
	}
	if !sameServerRuntime(server, next) {
		t.Fatal("routing changed server runtime comparison")
	}
	if next.Peers[0].Channel != "alternate" {
		t.Fatal("comparison mutated peer")
	}
	legacyJSON, _ := json.Marshal(next.Peers)
	legacySum := sha256.Sum256(legacyJSON)
	legacy := before
	legacy.PeersSHA256 = hex.EncodeToString(legacySum[:])
	auth := filepath.Join(root, "auth.json")
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(auth, data, 0600); err != nil {
		t.Fatal(err)
	}
	paths := ocservPaths{passwd: passwd, users: users, auth: auth}
	if ocservAuthHealth(paths, next) == nil {
		t.Fatal("legacy nonempty-channel fingerprint silently accepted")
	}
	data, _ = json.Marshal(after)
	if err := os.WriteFile(auth, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ocservAuthHealth(paths, next); err != nil {
		t.Fatal(err)
	}
	next.Peers[0].Credentials = map[string]string{}
	for k, v := range server.Peers[0].Credentials {
		next.Peers[0].Credentials[k] = v
	}
	next.Peers[0].Credentials["password"] = "changed-secret"
	changed, err := ocservStateFor(passwd, users, next)
	if err != nil || before == changed || sameServerRuntime(server, next) {
		t.Fatal("password change ignored")
	}
}

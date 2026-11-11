package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

func TestVPNProfileRetainedAcrossStoreReloadAndRedactedEdits(t *testing.T) {
	private, public, _ := generateWireGuardKeypair()
	serverPrivate, serverPublic, _ := generateWireGuardKeypair()
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{ID: "srv", Type: "wireguard", Config: map[string]any{"private_key": serverPrivate}, Peers: []config.VPNPeer{{ID: "phone", Enabled: true, Credentials: map[string]string{"private_key": private, "public_key": public, "preshared_key": "psk"}}}}}
	withKey, err := vpnservers.RenderWireGuard(cfg.VPNServers[0])
	if err != nil {
		t.Fatal(err)
	}
	delete(cfg.VPNServers[0].Peers[0].Credentials, "private_key")
	withoutKey, err := vpnservers.RenderWireGuard(cfg.VPNServers[0])
	if err != nil || withKey != withoutKey || strings.Contains(withKey, private) {
		t.Fatal("retaining a profile changed the runtime WireGuard configuration")
	}
	cfg.VPNServers[0].Peers[0].Credentials["private_key"] = private
	visible, err := redactAdminConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(visible)
	if strings.Contains(string(data), private) || strings.Contains(string(data), "psk") {
		t.Fatal("secret leaked into config")
	}
	mergeRedactedSecrets(visible, cfg)
	db := filepath.Join(t.TempDir(), "config.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateRevision(visible, "admin", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = st.MarkActive(id); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	revision, err := st.ActiveRevision()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{draft: revision.Config}
	request := func(role, peer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/profile", nil)
		r.SetPathValue("id", "srv")
		r.SetPathValue("peer", peer)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, role))
		w := httptest.NewRecorder()
		s.handleVPNClientProfile(w, r)
		return w
	}
	for i := 0; i < 2; i++ {
		w := request("admin", "phone")
		var got map[string]string
		json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != 200 || got["privateKey"] != private || got["serverPublicKey"] != serverPublic || got["presharedKey"] != "psk" || strings.Contains(w.Body.String(), serverPrivate) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("invalid profile response: status=%d", w.Code)
		}
	}
	if w := request("viewer", "phone"); w.Code != 403 || strings.Contains(w.Body.String(), private) {
		t.Fatal("viewer accessed profile")
	}
	if w := request("admin", "missing"); w.Code != 404 {
		t.Fatal("unknown peer accepted")
	}
	s.draft.VPNServers[0].Peers[0].Credentials["public_key"] = "changed"
	if w := request("admin", "phone"); w.Code != 409 || strings.Contains(w.Body.String(), private) {
		t.Fatal("mismatched key exported")
	}
	delete(s.draft.VPNServers[0].Peers[0].Credentials, "private_key")
	if w := request("admin", "phone"); w.Code != 409 {
		t.Fatal("legacy profile silently regenerated")
	}
}

func TestVPNPublicKeyEditDoesNotRetainUnrelatedPrivateKey(t *testing.T) {
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{ID: "srv", Type: "wireguard", Peers: []config.VPNPeer{{ID: "p", Credentials: map[string]string{"private_key": "old-private", "public_key": "old-public", "preshared_key": "psk"}}}}}
	next, _ := redactAdminConfig(cfg)
	next.VPNServers[0].Peers[0].Credentials["public_key"] = "new-public"
	mergeRedactedSecrets(next, cfg)
	creds := next.VPNServers[0].Peers[0].Credentials
	if _, exists := creds["private_key"]; exists || creds["preshared_key"] != "psk" {
		t.Fatal("public key replacement broke retained secrets")
	}
}

type vpnTelemetryRunner struct {
	outputs map[string]string
	fail    string
}

func (r vpnTelemetryRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name != "wg" || len(args) != 3 || args[0] != "show" || args[1] != "wg-srv1" {
		return "", fmt.Errorf("unexpected command")
	}
	if args[2] == r.fail {
		return "", fmt.Errorf("unavailable")
	}
	out, ok := r.outputs[args[2]]
	if !ok {
		return "", fmt.Errorf("unexpected field")
	}
	return out, nil
}
func (r vpnTelemetryRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestVPNClientTelemetry(t *testing.T) {
	now := time.Unix(10000, 0)
	srv := config.VPNServer{Type: "wireguard", Index: 1, Enabled: true}
	for _, key := range []string{"recent", "idle", "never", "missing", "disabled"} {
		srv.Peers = append(srv.Peers, config.VPNPeer{ID: key, Enabled: key != "disabled", Credentials: map[string]string{"public_key": key, "private_key": "must-not-leak"}})
	}
	runner := vpnTelemetryRunner{outputs: map[string]string{"latest-handshakes": "recent 9999\nidle 9000\nnever 0\n", "endpoints": "recent [2001:db8::1]:51820\nidle 192.0.2.2:1234\nnever (none)\n", "transfer": "recent 1048576 2097152\nidle 1 2\nnever 0 0\n"}}
	s := &Server{Collector: &runtime.Collector{Runner: runner}}
	rows := s.wireGuardClients(context.Background(), srv, now)
	for i, want := range []string{"recent", "idle", "never", "unknown", "disabled"} {
		if rows[i].State != want {
			t.Fatalf("%d: %s != %s", i, rows[i].State, want)
		}
	}
	if rows[0].Endpoint != "[2001:db8::1]:51820" || rows[0].Received != 1048576 || rows[0].Sent != 2097152 || rows[0].LastHandshake != 9999 {
		t.Fatal("telemetry lost")
	}
	data, _ := json.Marshal(rows)
	if strings.Contains(string(data), "must-not-leak") {
		t.Fatal("secret leaked")
	}
	runner.fail = "transfer"
	s.Collector.Runner = runner
	rows = s.wireGuardClients(context.Background(), srv, now)
	if rows[0].State != "unknown" || rows[0].LastHandshake != 0 {
		t.Fatal("failed polling reported stale online state")
	}
	runner.fail = ""
	runner.outputs["latest-handshakes"] = ""
	s.Collector.Runner = runner
	if s.wireGuardClients(context.Background(), srv, now)[0].State != "unknown" {
		t.Fatal("partial telemetry treated as never connected")
	}
	srv.Enabled = false
	if s.wireGuardClients(context.Background(), srv, now)[0].State != "server_disabled" {
		t.Fatal("disabled server reported online")
	}
}

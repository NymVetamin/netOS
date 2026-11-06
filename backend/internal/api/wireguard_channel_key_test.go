package api

import (
	"bytes"
	"context"
	"github.com/netos-router/netos/internal/config"
	"io"
	"net/http/httptest"
	"testing"
)

func TestWireGuardChannelPublicKey(t *testing.T) {
	private, public, err := generateWireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Channels = []config.Channel{{ID: "wg", Type: "wireguard", Config: map[string]any{"private_key": private, "preshared_key": "old"}}}
	s := &Server{draft: cfg}
	for _, tc := range []struct {
		section, level, body string
		status               int
	}{
		{"channels", "manage", `{"channel_id":"wg"}`, 200},
		{"channels", "view", `{"channel_id":"wg"}`, 403},
		{"vpn-servers", "manage", `{"channel_id":"wg"}`, 403},
		{"channels", "manage", `{"channel_id":"missing"}`, 404},
		{"channels", "manage", `{"channel_id":"wg","server_id":"other"}`, 403},
	} {
		r := limitedRequest(map[string]string{tc.section: tc.level})
		r.Method = "POST"
		r.Body = io.NopCloser(bytes.NewBufferString(tc.body))
		r.ContentLength = int64(len(tc.body))
		// Use the test draft, not a user's persistent private draft.
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, ""))
		w := httptest.NewRecorder()
		s.handleWireGuardKeypair(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s/%s status %d", tc.section, tc.level, w.Code)
		}
		if bytes.Contains(w.Body.Bytes(), []byte(private)) {
			t.Fatal("private key disclosed")
		}
		if tc.status == 200 && !bytes.Contains(w.Body.Bytes(), []byte(public)) {
			t.Fatal("wrong public key")
		}
	}
	next := *cfg
	next.Channels = []config.Channel{{ID: "wg", Type: "wireguard", Config: map[string]any{"private_key": private}}}
	mergeRedactedSecrets(&next, cfg)
	if _, ok := next.Channels[0].Config["preshared_key"]; ok {
		t.Fatal("import without PSK retained old PSK")
	}
	if cfg.Channels[0].Config["private_key"] != private {
		t.Fatal("derivation rotated stored key")
	}
}

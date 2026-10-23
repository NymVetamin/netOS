package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func TestSocksEmptySelectionDoesNotLeavePrivateDraft(t *testing.T) {
	s, _, _, _ := transactionServer(t)
	request := func(method string, cfg *config.Config, version uint64) configResponse {
		t.Helper()
		body, _ := json.Marshal(cfg)
		r := httptest.NewRequest(method, "/api/config", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, "admin"))
		r = withPanelAccess(r, "admin", store.PanelAccess{Enabled: true})
		r.Header.Set("If-Match", strconv.FormatUint(version, 10))
		w := httptest.NewRecorder()
		if method == "GET" {
			s.handleGetConfig(w, r)
		} else {
			s.handleSaveConfig(w, r)
		}
		if w.Code != 200 {
			t.Fatalf("status=%d: %s", w.Code, w.Body.String())
		}
		var got configResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := request("GET", nil, 0)
	for i := 0; i < 2; i++ {
		got.Config.Socks.VPNs = []string{"wgserv"}
		got = request("PUT", got.Config, got.DraftVersion)
		if !got.Dirty {
			t.Fatal("VPN selection lost")
		}
		got.Config.Socks.VPNs = []string{}
		got.Config.Socks.Networks = []string{}
		got = request("PUT", got.Config, got.DraftVersion)
		if got.Dirty {
			t.Fatal("empty SOCKS selections leave a dirty draft")
		}
		got = request("GET", nil, 0)
		if got.Dirty {
			t.Fatal("draft reappeared after reload")
		}
	}
	got.Config.System.Hostname = "keep-this-change"
	got.Config.Socks.VPNs = []string{}
	got = request("PUT", got.Config, got.DraftVersion)
	if !got.Dirty {
		t.Fatal("unrelated real change was discarded")
	}
}

func TestSameConfigSocksEmptyListsWithoutMutation(t *testing.T) {
	a, b := config.Default(), config.Default()
	a.Socks.Enabled, b.Socks.Enabled = true, true
	a.Socks.Networks, a.Socks.VPNs = nil, nil
	b.Socks.Networks, b.Socks.VPNs = []string{}, []string{}
	if !sameConfig(a, b) || !sameConfig(b, a) {
		t.Fatal("nil and empty SOCKS selections differ")
	}
	if a.Socks.VPNs != nil || b.Socks.VPNs == nil {
		t.Fatal("comparison mutated input")
	}
	b.Socks.VPNs = []string{"wgserv"}
	if sameConfig(a, b) {
		t.Fatal("nonempty selection ignored")
	}
	b.Socks.VPNs = nil
	b.Socks.Port++
	if sameConfig(a, b) {
		t.Fatal("port change ignored")
	}
}

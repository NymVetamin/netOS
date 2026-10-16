package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func limitedRequest(permissions map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/api/config", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, "operator"))
	return withPanelAccess(r, "limited", store.PanelAccess{Enabled: true, Permissions: permissions})
}

func TestScopedConfigRejectsHiddenChanges(t *testing.T) {
	cfg := config.Default()
	r := limitedRequest(map[string]string{"clients": "manage", "map": "view"})
	shown, err := scopedConfig(r, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(shown.Firewall.Rules) != 0 {
		t.Fatal("firewall leaked")
	}
	merged, err := mergeScopedConfig(r, cfg, shown)
	if err != nil {
		t.Fatal(err)
	}
	if !sameConfig(merged, cfg) {
		t.Fatal("unchanged projection changes config")
	}
	shown.System.Timezone = "Etc/GMT+3"
	if _, err := mergeScopedConfig(r, cfg, shown); err == nil {
		t.Fatal("forbidden system change accepted")
	}
}

func TestLimitedRoutesAndDraftIsolation(t *testing.T) {
	s, adminCookie, adminCSRF, _ := transactionServer(t)
	u := store.PanelUser{Username: "operator", Role: "limited", PanelAccess: store.PanelAccess{Enabled: true, Permissions: map[string]string{"system": "manage"}}}
	if err := s.Store.SavePanelUser(u, "hash", true, false, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateSession("limited-token", "operator", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	s.csrfTokens["limited-token"] = "limited-csrf"
	cookie := &http.Cookie{Name: sessionCookie, Value: "limited-token"}
	h := s.Routes()
	for _, path := range []string{"/api/panel-users", "/api/backups", "/api/render", "/api/firewall/live", "/api/vpn-servers/test/clients", "/api/clients"} {
		if w := serveAuthed(h, "GET", path, nil, cookie, ""); w.Code != 403 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	s.draft = config.Default()
	s.draft.System.Hostname = "admin-private"
	w := serveAuthed(h, "GET", "/api/config", nil, cookie, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var response configResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Config.System.Hostname == "admin-private" || response.Dirty {
		t.Fatal("admin draft leaked")
	}
	response.Config.System.Hostname = "operator-private"
	body, _ := json.Marshal(response.Config)
	// Save with the same optimistic concurrency contract used by the UI.
	saved := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/config", bytes.NewReader(body))
	request.AddCookie(cookie)
	request.Header.Set(csrfHeader, "limited-csrf")
	request.Header.Set("If-Match", "1")
	h.ServeHTTP(saved, request)
	if saved.Code != 200 {
		t.Fatalf("save: %d %s", saved.Code, saved.Body.String())
	}
	if s.draft.System.Hostname != "admin-private" {
		t.Fatal("private save overwrote admin draft")
	}
	w = serveAuthed(h, "POST", "/api/config/apply", []byte(`{"draft_version":2}`), cookie, "limited-csrf")
	if w.Code != 409 {
		t.Fatalf("apply over admin draft: %d %s", w.Code, w.Body.String())
	}
	w = serveAuthed(h, "GET", "/api/config", nil, adminCookie, adminCSRF)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	s.draft = nil
	w = serveAuthed(h, "POST", "/api/config/apply", []byte(`{"draft_version":2}`), cookie, "limited-csrf")
	if w.Code != 200 {
		t.Fatalf("private apply: %d %s", w.Code, w.Body.String())
	}
	if s.Engine.Current().System.Hostname != "operator-private" {
		t.Fatal("private apply did not change active config")
	}
	if pending, _ := s.Engine.Pending(); !pending {
		t.Fatal("expected confirmation")
	}
	other := u
	other.Username = "other"
	if err := s.Store.SavePanelUser(other, "hash", true, false, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateSession("other-token", "other", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	s.csrfTokens["other-token"] = "other-csrf"
	otherCookie := &http.Cookie{Name: sessionCookie, Value: "other-token"}
	for _, action := range []string{"confirm", "rollback"} {
		w = serveAuthed(h, "POST", "/api/config/"+action, []byte(`{}`), otherCookie, "other-csrf")
		if w.Code != 403 {
			t.Fatalf("other user %s: %d %s", action, w.Code, w.Body.String())
		}
	}
	w = serveAuthed(h, "POST", "/api/config/confirm", []byte(`{}`), cookie, "limited-csrf")
	if w.Code != 200 {
		t.Fatalf("private confirm: %d %s", w.Code, w.Body.String())
	}
	w = serveAuthed(h, "GET", "/api/config", nil, cookie, "")
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Dirty || response.DraftVersion <= 2 {
		t.Fatalf("private version reused: %+v", response)
	}
	u.Enabled = false
	if err := s.Store.SavePanelUser(u, "", false, false, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	w = serveAuthed(h, "GET", "/api/config", nil, cookie, "")
	if w.Code != 401 {
		t.Fatalf("disabled session: %d", w.Code)
	}
}

func TestAllSectionProjectionsPreserveUnchangedConfig(t *testing.T) {
	for section := range panelSections {
		t.Run(section, func(t *testing.T) {
			cfg := config.Default()
			r := limitedRequest(map[string]string{section: "manage"})
			shown, err := scopedConfig(r, cfg)
			if err != nil {
				t.Fatal(err)
			}
			merged, err := mergeScopedConfig(r, cfg, shown)
			if err != nil {
				t.Fatal(err)
			}
			if !sameConfig(merged, cfg) {
				t.Fatal("projection changed unrelated configuration")
			}
		})
	}
}

func TestClientsCanOnlyChangeVPNExit(t *testing.T) {
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{ID: "srv", Name: "server", Type: "wireguard", Subnet: "10.9.0.1/24", Config: map[string]any{"private_key": "secret"}, Peers: []config.VPNPeer{{ID: "peer", Name: "phone", Credentials: map[string]string{"private_key": "client-secret"}}}}}
	r := limitedRequest(map[string]string{"clients": "manage"})
	shown, err := scopedConfig(r, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(shown.VPNServers[0].Config) != 0 || len(shown.VPNServers[0].Peers[0].Credentials) != 0 {
		t.Fatal("VPN keys leaked to clients section")
	}
	shown.VPNServers[0].Peers[0].Channel = "direct"
	merged, err := mergeScopedConfig(r, cfg, shown)
	if err != nil {
		t.Fatal(err)
	}
	if merged.VPNServers[0].Config["private_key"] != "secret" || merged.VPNServers[0].Peers[0].Credentials["private_key"] != "client-secret" {
		t.Fatal("secret lost")
	}
	if merged.VPNServers[0].Peers[0].Channel != "direct" {
		t.Fatal("channel not changed")
	}
	shown.VPNServers[0].Peers[0].Name = "forged"
	if _, err := mergeScopedConfig(r, cfg, shown); err == nil {
		t.Fatal("peer mutation accepted without VPN permission")
	}
}

func TestNetworkPermissionOnlyChangesUplinkNAT(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "wan", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "wan", Name: "Uplink", Interface: "wan", Enabled: true, Proto: "dhcp"}}
	cfg.Firewall.NAT = []config.NATRule{{ID: "auto", Name: "NAT", System: true, Enabled: true, Interface: "eth0", Direction: "source"}, {ID: "other", System: true, Enabled: true, Interface: "tun-ch1", Direction: "source"}}
	r := limitedRequest(map[string]string{"network": "manage", "firewall": "view"})
	shown, err := scopedConfig(r, cfg)
	if err != nil {
		t.Fatal(err)
	}
	shown.Firewall.NAT[0].Enabled = false
	merged, err := mergeScopedConfig(r, cfg, shown)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Firewall.NAT[0].Enabled || !merged.Firewall.NAT[1].Enabled {
		t.Fatal("wrong NAT changed")
	}
	shown.Firewall.NAT[1].Enabled = false
	if _, err := mergeScopedConfig(r, cfg, shown); err == nil {
		t.Fatal("network manager changed tunnel NAT")
	}
	channelRequest := limitedRequest(map[string]string{"channels": "manage"})
	shown, err = scopedConfig(channelRequest, cfg)
	if err != nil {
		t.Fatal(err)
	}
	shown.WANs[0].Enabled = false
	if _, err := mergeScopedConfig(channelRequest, cfg, shown); err == nil {
		t.Fatal("channel permission allowed WAN mutation")
	}
}

func TestFirewallPreviewPermissions(t *testing.T) {
	for _, level := range []string{"", "view", "manage"} {
		r := limitedRequest(map[string]string{"firewall": level})
		r.Method = "POST"
		r.URL.Path = "/api/firewall/preview"
		if limitedEndpoint(r) != (level != "") {
			t.Fatalf("preview permission %q", level)
		}
	}
}

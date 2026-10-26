package api

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func TestPlanSchemaCoverage(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var visit func(reflect.Type)
	visit = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			if !f.IsExported() || key == "-" {
				continue
			}
			if f.Tag.Get("plan") == "" {
				t.Errorf("%s.%s: add an explicit plan label for %q", typ.Name(), f.Name, key)
			}
			if exposure := f.Tag.Get("sensitivity"); exposure != "public" && exposure != "secret" {
				t.Errorf("%s.%s: classify value visibility", typ.Name(), f.Name)
			}
			if f.Tag.Get("plan") == "-" && key != "secrets_set" && key != "reality_key_set" {
				t.Errorf("%s.%s: editable settings must not be omitted", typ.Name(), f.Name)
			}
			if format := f.Tag.Get("format"); format != "" && format != "mbit" && format != "switch" {
				t.Errorf("unsupported display format %q", format)
			}
			visit(f.Type)
		}
	}
	visit(reflect.TypeOf(config.Config{}))
	for _, typ := range planChannelSchemas {
		visit(typ)
	}
	for _, typ := range planServerSchemas {
		visit(typ)
	}

}

func TestPlanReportsEveryTypedSetting(t *testing.T) {
	cfg := config.Config{}
	count := 0
	var visit func(reflect.Value, string)
	visit = func(v reflect.Value, path string) {
		switch v.Kind() {
		case reflect.Pointer:
			v.Set(reflect.New(v.Type().Elem()))
			visit(v.Elem(), path)
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				f := v.Type().Field(i)
				if f.IsExported() && f.Tag.Get("plan") != "-" {
					visit(v.Field(i), path+"/"+f.Name)
				}
			}
		case reflect.Slice:
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			visit(v.Index(0), path+"/0")
		case reflect.String, reflect.Bool, reflect.Int, reflect.Int64, reflect.Uint, reflect.Uint64:
			before, err := objectConfig(configObject(&cfg))
			if err != nil {
				t.Fatal(err)
			}
			saved := reflect.ValueOf(v.Interface())
			switch v.Kind() {
			case reflect.String:
				v.SetString("plan-test-value")
			case reflect.Bool:
				v.SetBool(true)
			case reflect.Int, reflect.Int64:
				v.SetInt(1)
			default:
				v.SetUint(1)
			}
			if changes := configurationChanges(before, &cfg); len(changes) == 0 {
				t.Errorf("setting omitted: %s", path)
			}
			count++
			v.Set(saved)
		}
	}
	visit(reflect.ValueOf(&cfg).Elem(), "")
	if count < 250 {
		t.Fatalf("unexpected schema coverage: %d", count)
	}
	t.Logf("checked %d typed setting mutations", count)
}

func TestPlanEndpointReturnsDetailsWithoutChangingDraft(t *testing.T) {
	s, cookie, csrf, _ := transactionServer(t)
	base := s.Engine.Current()
	next, _ := objectConfig(configObject(base))
	next.System.Hostname = "new-name"
	s.draftMu.Lock()
	d := s.privateDraftLocked("admin")
	d.Config = next
	version := d.Version
	s.draftMu.Unlock()
	w := serveAuthed(s.Routes(), "POST", "/api/config/plan", nil, cookie, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result planResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 || result.Changes[0].Path != "/system/hostname" || result.Changes[0].After != "new-name" || !result.NeedsConfirm {
		t.Fatal(w.Body.String())
	}
	if d.Version != version || d.Config != next || s.Engine.Current() != base {
		t.Fatal("preview changed transaction state")
	}
}

func TestPlanDoesNotDescribeAnInFlightTransaction(t *testing.T) {
	s, cookie, csrf, _ := transactionServer(t)
	s.draftMu.Lock()
	s.draftApplying = true
	s.draftMu.Unlock()
	w := serveAuthed(s.Routes(), "POST", "/api/config/plan", nil, cookie, csrf)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	s.draftMu.Lock()
	s.draftApplying = false
	s.draftMu.Unlock()
	applyDraft(t, s, cookie, csrf, "pending-plan-test")
	w = serveAuthed(s.Routes(), "POST", "/api/config/plan", nil, cookie, csrf)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = serveAuthed(s.Routes(), "POST", "/api/config/rollback", nil, cookie, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = serveAuthed(s.Routes(), "POST", "/api/config/plan", nil, cookie, csrf)
	if w.Code != 200 {
		t.Fatal("plan did not recover after rollback", w.Code, w.Body.String())
	}
}

func TestPlanKnownProviderAndWireGuardProfile(t *testing.T) {
	a := config.Default()
	a.Channels = []config.Channel{{ID: "wg", Type: "wireguard", Config: map[string]any{"endpoint": "old.example:1234"}}}
	a.VPNServers = []config.VPNServer{{ID: "server", Type: "wireguard", Peers: []config.VPNPeer{{ID: "peer", WireGuardProfile: &config.WireGuardClientProfile{UseRouterDNS: false}}}}}
	b, _ := objectConfig(configObject(a))
	b.Channels[0].Config["endpoint"] = "new.example:4321"
	b.VPNServers[0].Peers[0].WireGuardProfile.UseRouterDNS = true
	changes := configurationChanges(a, b)
	raw, _ := json.Marshal(changes)
	if len(changes) != 2 || !strings.Contains(string(raw), "new.example:4321") || !strings.Contains(string(raw), "Использовать DNS роутера") {
		t.Fatal(string(raw))
	}
}

func TestPlanChangesConcreteAndReadOnly(t *testing.T) {
	a := config.Default()
	a.DHCP.Provider = "dnsmasq"
	a.WANs = []config.WAN{{ID: "wan1", Name: "Аплинк", Enabled: true}}
	a.Clients = []config.Client{{ID: "phone", Name: "Телефон", Channel: "direct"}}
	b, _ := objectConfig(configObject(a))
	b.WANs[0].Enabled = false
	b.Clients[0].Channel = "vpn"
	b.DHCP.Provider = "kea"
	initialA, _ := json.Marshal(a)
	initialB, _ := json.Marshal(b)
	changes := configurationChanges(a, b)
	want := map[string][2]string{"/wans/wan1/enabled": {"Включено", "Выключено"}, "/clients/phone/channel": {"Напрямую", "vpn"}, "/dhcp/provider": {a.DHCP.Provider, "kea"}}
	for _, c := range changes {
		if w, ok := want[c.Path]; ok {
			if c.Before != w[0] || c.After != w[1] {
				t.Errorf("%+v", c)
			}
			delete(want, c.Path)
		}
	}
	if len(want) > 0 {
		t.Fatal("missing changes", want, changes)
	}
	afterA, _ := json.Marshal(a)
	afterB, _ := json.Marshal(b)
	if string(initialA) != string(afterA) || string(initialB) != string(afterB) {
		t.Fatal("plan mutated configs")
	}
}

func TestPlanSecretsAndUnknownProviderFields(t *testing.T) {
	a := config.Default()
	a.Socks.Password = "old-secret"
	a.Channels = []config.Channel{{ID: "ch", Config: map[string]any{"outbound": map[string]any{"settings": map[string]any{"users": []any{map[string]any{"id": "old-uuid", "futureAuth": "old-token"}}}}}}}
	b, _ := objectConfig(configObject(a))
	b.Socks.Password = "new-secret"
	b.Channels[0].Config = map[string]any{"outbound": map[string]any{"settings": map[string]any{"users": []any{map[string]any{"id": "new-uuid", "futureAuth": "new-token"}}}}, "futureOption": 42}
	changes := configurationChanges(a, b)
	raw, _ := json.Marshal(changes)
	s := string(raw)
	for _, secret := range []string{"old-secret", "new-secret", "old-uuid", "new-uuid", "old-token", "new-token"} {
		if strings.Contains(s, secret) {
			t.Fatal("secret leaked", s)
		}
	}
	for _, path := range []string{"/socks/password", "/channels/ch/config/outbound/settings/users/0/id", "/channels/ch/config/futureOption"} {
		if !strings.Contains(s, path) {
			t.Fatal("change omitted", path, s)
		}
	}
}

func TestPlanOpaqueMissingNullAndEmptyAreDistinct(t *testing.T) {
	for _, next := range []any{nil, map[string]any{}, []any{}, []any{nil}} {
		a := config.Default()
		a.Channels = []config.Channel{{ID: "ch", Config: map[string]any{}}}
		b, _ := objectConfig(configObject(a))
		b.Channels[0].Config = map[string]any{"future": next}
		changes := configurationChanges(a, b)
		if len(changes) == 0 {
			t.Fatalf("missing -> %#v omitted", next)
		}
		if changes := configurationChanges(b, a); len(changes) == 0 {
			t.Fatalf("%#v -> missing omitted", next)
		}
	}
}

func TestPlanUnknownTypeChangesDoNotLeak(t *testing.T) {
	for _, replacement := range []any{nil, map[string]any{}, []any{}, map[string]any{"futureChild": "new-secret"}, []any{"new-secret"}} {
		a := config.Default()
		a.Channels = []config.Channel{{ID: "ch", Config: map[string]any{"future": "old-secret"}}}
		b, _ := objectConfig(configObject(a))
		b.Channels[0].Config["future"] = replacement
		for _, pair := range [][2]*config.Config{{a, b}, {b, a}} {
			raw, _ := json.Marshal(configurationChanges(pair[0], pair[1]))
			if strings.Contains(string(raw), "old-secret") || strings.Contains(string(raw), "new-secret") {
				t.Fatal(string(raw))
			}
		}
	}
}

func TestPlanFreeformDaemonConfigIsNotDisclosed(t *testing.T) {
	a := config.Default()
	b, _ := objectConfig(configObject(a))
	b.DNS.AdvancedOptions = "password=private-probe-value"
	raw, _ := json.Marshal(configurationChanges(a, b))
	if strings.Contains(string(raw), "private-probe-value") || !strings.Contains(string(raw), "advanced_options") {
		t.Fatal(string(raw))
	}
}

func TestPlanIdentityOrderCreationAndEmptyLists(t *testing.T) {
	a := config.Default()
	a.Socks.VPNs = nil
	a.Channels = []config.Channel{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}}
	b, _ := objectConfig(configObject(a))
	b.Socks.VPNs = []string{}
	if changes := configurationChanges(a, b); len(changes) != 0 {
		t.Fatal("empty list false positive", changes)
	}
	b.Channels[0], b.Channels[1] = b.Channels[1], b.Channels[0]
	changes := configurationChanges(a, b)
	if len(changes) != 1 || changes[0].Kind != "reorder" {
		t.Fatal(changes)
	}
	b.Channels = []config.Channel{{ID: "b", Name: "B"}, {ID: "c", Name: "C"}}
	kinds := map[string]bool{}
	for _, c := range configurationChanges(a, b) {
		kinds[c.Kind] = true
		if strings.Contains(c.Path, "/b/") {
			t.Fatal("unchanged object treated as edited", c)
		}
	}
	if !kinds["add"] || !kinds["remove"] || !kinds["reorder"] {
		t.Fatal(kinds)
	}
}

func TestPlanProjectionAndExecutionContract(t *testing.T) {
	a := config.Default()
	b, _ := objectConfig(configObject(a))
	b.Socks.Password = "hidden-password"
	b.System.Hostname = "hidden-host"
	b.Clients = []config.Client{{ID: "client", Name: "visible-client"}}
	r := withPanelAccess(httptest.NewRequest("POST", "/api/config/plan", nil), "limited", store.PanelAccess{Enabled: true, Permissions: map[string]string{"clients": "manage"}})
	actions := []apply.Action{{Subsystem: "wan", Kind: "update", Disruptive: true}}
	res, err := describePlan(r, a, b, actions, 23)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res.Changes)
	s := string(raw)
	if strings.Contains(s, "hidden-") || !strings.Contains(s, "visible-client") {
		t.Fatal(s)
	}
	if !reflect.DeepEqual(actions, res.Actions) || res.NeedsConfirm != apply.NeedsConfirmation(actions) || res.DraftVersion != 23 {
		t.Fatal(res)
	}
	for _, safe := range []bool{true, false} {
		actions[0].Disruptive = !safe
		actions[0].Confirmation = apply.ConfirmationSafe
		res, err = describePlan(r, a, b, actions, 23)
		if err != nil || res.NeedsConfirm != apply.NeedsConfirmation(actions) {
			t.Fatal(res, err)
		}
	}
}

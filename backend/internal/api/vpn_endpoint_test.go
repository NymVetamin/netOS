package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/subsys/ddns"
)

func TestVPNEndpointSuggestion(t *testing.T) {
	for _, tc := range []struct {
		name, domain, iface, external, want, source string
		fail                                        bool
		calls                                       int
	}{
		{name: "DNS first", domain: "router.example.com", want: "router.example.com", source: "ddns", calls: 0},
		{name: "public WAN", iface: "8.8.4.4", want: "8.8.4.4", source: "wan", calls: 1},
		{name: "private NAT", iface: "192.168.1.2", external: "8.8.8.8", want: "8.8.8.8", source: "external", calls: 2},
		{name: "CGNAT", iface: "100.64.1.2", external: "1.1.1.1", want: "1.1.1.1", source: "external", calls: 2},
		{name: "failure", iface: "10.0.0.1", fail: true, calls: 2},
		{name: "invalid external", iface: "10.0.0.1", external: "127.0.0.1", calls: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DDNS = config.DDNS{Enabled: tc.domain != "", Hostname: tc.domain, Token: "must remain unchanged"}
			cfg.WANs = []config.WAN{{ID: "disabled", Metric: 0}, {ID: "backup", Enabled: true, Metric: 100}, {ID: "primary", Enabled: true, Metric: 10}}
			original := cfg.DDNS
			calls := 0
			resolver := &ddns.Controller{ResolveAddress: func(ctx context.Context, c *config.Config) (string, error) {
				calls++
				if c.DDNS.AddressSource == "interface" {
					if c.DDNS.WAN != "primary" {
						t.Fatal("wrong WAN")
					}
					return tc.iface, nil
				}
				if tc.fail {
					return "", errors.New("secret transport detail")
				}
				return tc.external, nil
			}}
			got, err := suggestVPNEndpoint(context.Background(), cfg, resolver)
			if got.Host != tc.want || got.Source != tc.source || calls != tc.calls {
				t.Fatalf("got %+v calls%d", got, calls)
			}
			if (err != nil) != (tc.want == "") {
				t.Fatalf("unexpected error %v", err)
			}
			if !reflect.DeepEqual(cfg.DDNS, original) {
				t.Fatal("discovery changed configuration")
			}
		})
	}
}
func TestVPNEndpointRejectsNonPublicAddresses(t *testing.T) {
	for _, s := range []string{"", "not an IP", "::1", "0.1.2.3", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.127.1.1", "169.254.1.1", "198.19.0.1", "224.0.0.1", "255.255.255.255"} {
		if publicVPNIPv4(s) {
			t.Errorf("accepted %q", s)
		}
	}
}
func TestVPNEndpointPermissions(t *testing.T) {
	for _, section := range []string{"vpn-servers", "services", "clients"} {
		r := withPanelAccess(httptest.NewRequest("GET", "/api/vpn-endpoint", nil), "user", store.PanelAccess{Permissions: map[string]string{section: "view"}})
		if limitedEndpoint(r) != (section == "vpn-servers") {
			t.Errorf("wrong access for %s", section)
		}
	}
}

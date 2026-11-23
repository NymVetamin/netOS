package api

import (
	"net/http/httptest"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func TestDDNSSecretsStayWithProvider(t *testing.T) {
	for _, role := range []string{"admin", "limited"} {
		for _, from := range []string{"duckdns", "cloudflare", "noip"} {
			for _, to := range []string{"duckdns", "cloudflare", "noip"} {
				for _, enabled := range []bool{true, false} {
					t.Run(role+"/"+from+"/"+to+"/"+map[bool]string{true: "enabled", false: "disabled"}[enabled], func(t *testing.T) {
						previous := config.Default()
						previous.DDNS = config.DDNS{Enabled: enabled, Provider: from, Hostname: "router.duckdns.org", AddressSource: "web", Interval: 300,
							Token: "old-token", Password: "old-password", Username: "user", ZoneID: "zone", RecordID: "record"}
						r := withPanelAccess(httptest.NewRequest("PUT", "/api/config", nil), role, store.PanelAccess{Enabled: true, Permissions: map[string]string{"services": "manage"}})
						visible, err := scopedConfig(r, previous)
						if err != nil {
							t.Fatal(err)
						}
						visible.DDNS.Provider = to
						next, err := mergeScopedConfig(r, previous, visible)
						if err != nil {
							t.Fatal(err)
						}
						wantToken, wantPassword := "", ""
						if from == to {
							wantToken, wantPassword = "old-token", "old-password"
						}
						if next.DDNS.Token != wantToken || next.DDNS.Password != wantPassword {
							t.Fatal("stored credentials crossed provider identity")
						}
						if next.Validate().HasErrors() != (enabled && from != to) {
							t.Fatal("changed provider must require new credentials", next.Validate().Problems)
						}
						visible.DDNS.Token, visible.DDNS.Password = "new-token", "new-password"
						next, err = mergeScopedConfig(r, previous, visible)
						if err != nil || next.DDNS.Token != "new-token" || next.DDNS.Password != "new-password" || next.Validate().HasErrors() {
							t.Fatal("explicit replacement failed", err)
						}
						visible, err = scopedConfig(r, next)
						if err != nil {
							t.Fatal(err)
						}
						visible.DDNS.Interval = 600
						again, err := mergeScopedConfig(r, next, visible)
						if err != nil || again.DDNS.Token != "new-token" || again.DDNS.Password != "new-password" || again.DDNS.Interval != 600 {
							t.Fatal("ordinary edit lost fresh credentials", err)
						}
						if previous.DDNS.Provider != from || previous.DDNS.Token != "old-token" || previous.DDNS.Password != "old-password" {
							t.Fatal("merge mutated previous config")
						}
					})
				}
			}
		}
	}
}

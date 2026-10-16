package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/netos-router/netos/internal/store"
)

type accessContextKey struct{}

func may(r *http.Request, section string, manage bool) bool {
	if roleOf(r) == "admin" {
		return true
	}
	a, _ := r.Context().Value(accessContextKey{}).(store.PanelAccess)
	level := a.Permissions[section]
	return level == "manage" || (!manage && level == "view")
}

func anySection(r *http.Request, manage bool, sections ...string) bool {
	for _, section := range sections {
		if may(r, section, manage) {
			return true
		}
	}
	return false
}

// Explicit allow-list: newly added endpoints are never implicitly delegated.
func limitedEndpoint(r *http.Request) bool {
	p := r.URL.Path
	write := r.Method != http.MethodGet
	if p == "/api/session" || p == "/api/logout" || p == "/api/password" {
		return true
	}
	if p == "/api/config" || strings.HasPrefix(p, "/api/config/") {
		for section := range panelSections {
			if may(r, section, write) {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(p, "/api/vpn-servers/") {
		if strings.HasSuffix(p, "/certificate") && !strings.Contains(p, "/peers/") && !write {
			return may(r, "vpn-servers", false)
		}
		if strings.HasSuffix(p, "/clients") && !write {
			return anySection(r, false, "clients", "map", "vpn-servers", "dashboard")
		}
		return may(r, "vpn-servers", true)
	}
	if strings.HasPrefix(p, "/api/interfaces/") {
		return !write && may(r, "network", false)
	}
	switch p {
	case "/api/status":
		return !write
	case "/api/catalog":
		return !write && anySection(r, false, "components", "services", "channels", "network", "vpn-servers", "wifi", "storage")
	case "/api/clients", "/api/leases", "/api/arp":
		return !write && anySection(r, false, "clients", "map", "dashboard", "services", "diagnostics")
	case "/api/interfaces":
		return !write && anySection(r, false, "network", "map", "dashboard", "channels", "routing", "firewall", "traffic", "wifi")
	case "/api/routes":
		return !write && anySection(r, false, "routing", "diagnostics")
	case "/api/statistics":
		return !write && anySection(r, false, "dashboard", "traffic")
	case "/api/storage/devices":
		return !write && may(r, "storage", false)
	case "/api/ddns/status":
		return !write && may(r, "services", false)
	case "/api/dns/blocklists/status", "/api/socks/status":
		return !write && may(r, "services", false)
	case "/api/socks/credentials":
		return may(r, "services", true)
	case "/api/firewall/live":
		return !write && may(r, "firewall", false)
	case "/api/logs":
		return !write && may(r, "diagnostics", false)
	case "/api/diagnostics/probe":
		return may(r, "diagnostics", true)
	case "/api/revisions", "/api/audit":
		return !write && may(r, "history", false)
	case "/api/maintenance/status", "/api/maintenance/releases":
		return !write && may(r, "system", false)
	case "/api/certificates":
		return !write && anySection(r, false, "system", "vpn-servers")
	case "/api/wireguard/keypair", "/api/xray/keypair":
		return anySection(r, true, "channels", "vpn-servers")
	}
	// Backups, restore, updates and raw generated configs are administrator-only:
	// they can expose or replace the complete configuration, including users.
	return false
}

func withPanelAccess(r *http.Request, role string, access store.PanelAccess) *http.Request {
	ctx := context.WithValue(r.Context(), ctxRole, role)
	return r.WithContext(context.WithValue(ctx, accessContextKey{}, access))
}

package vpnservers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/system"
	"github.com/netos-router/netos/internal/tlsutil"
)

func xrayUnitName(server config.VPNServer) string {
	return fmt.Sprintf("netos-xray-srv%d.service", server.Index)
}

func (s *Subsystem) xrayPaths(server config.VPNServer) (string, string) {
	return filepath.Join(s.StateDir, fmt.Sprintf("xray-srv%d.json", server.Index)),
		filepath.Join(s.UnitDir, xrayUnitName(server))
}

func RenderXray(server config.VPNServer, cfg *config.Config) ([]byte, error) {
	certDir := filepath.Join("/var/lib/netos/generated", fmt.Sprintf("xray-srv%d-tls", server.Index))
	return renderXrayWithTLS(server, cfg, filepath.Join(certDir, "panel.crt"), filepath.Join(certDir, "panel.key"))
}

func renderXrayWithTLS(server config.VPNServer, cfg *config.Config, certPath, keyPath string) ([]byte, error) {
	xr, err := server.XrayConfig()
	if err != nil {
		return nil, err
	}
	protocol := xr.Protocol
	if protocol == "" {
		protocol = "reality"
	}
	clients := make([]any, 0, len(server.Peers))
	// Xray applies an implicit private/reserved-address block to freedom
	// outbounds used by VLESS servers. Reality here is an authenticated VPN
	// entry point, so netOS firewall policy is the authority for reachable
	// destinations, just as it is for WireGuard and the other VPN servers.
	freedomSettings := map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}}
	outbounds := []any{map[string]any{"tag": "direct", "protocol": "freedom", "settings": freedomSettings}}
	rules := []any{}
	channelByID := map[string]config.Channel{}
	for _, channel := range cfg.Channels {
		if channel.Enabled {
			channelByID[channel.ID] = channel
		}
	}
	tags := map[string]bool{"direct": true}
	outboundTag := func(channelID string) string {
		if channel, ok := channelByID[channelID]; ok && channel.Type != "direct" {
			tag := "channel-" + channel.ID
			if !tags[tag] {
				outbounds = append(outbounds, map[string]any{
					"tag": tag, "protocol": "freedom", "settings": freedomSettings,
					"streamSettings": map[string]any{"sockopt": map[string]any{"mark": channels.Mark(channel)}},
				})
				tags[tag] = true
			}
			return tag
		}
		return "direct"
	}
	emails := map[string]string{}
	defaultRules := []any{}
	for _, peer := range server.Peers {
		if !peer.Enabled {
			continue
		}
		email := server.ID + "/" + peer.ID
		client := map[string]any{"email": email}
		switch protocol {
		case "reality", "vless", "vmess":
			client["id"] = peer.Credentials["uuid"]
			if protocol == "reality" && xr.Flow != "" {
				client["flow"] = xr.Flow
			}
		case "trojan", "shadowsocks":
			client["password"] = peer.Credentials["password"]
		case "hysteria":
			client["auth"] = peer.Credentials["password"]
		case "wireguard":
			client["publicKey"] = peer.Credentials["public_key"]
			client["allowedIPs"] = []string{peer.Address + "/32"}
			if psk := peer.Credentials["preshared_key"]; psk != "" {
				client["preSharedKey"] = psk
			}
		case "socks", "http":
			client = map[string]any{"user": peer.Credentials["username"], "pass": peer.Credentials["password"]}
		}
		clients = append(clients, client)
		emails[peer.ID] = email
		channelID := peer.Channel
		if channelID == "" {
			channelID = server.DefaultChannel
		}
		if protocol == "socks" || protocol == "http" {
			defaultRules = append(defaultRules, map[string]any{"type": "field", "inboundTag": []string{"xray-in"}, "outboundTag": outboundTag(channelID)})
		} else {
			defaultRules = append(defaultRules, map[string]any{"type": "field", "user": []string{email}, "outboundTag": outboundTag(channelID)})
		}
	}
	policies := append([]config.Policy(nil), cfg.Policies...)
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority < policies[j].Priority
		}
		return policies[i].ID < policies[j].ID
	})
	for _, policy := range policies {
		if !policy.Enabled || policy.VPNServer != server.ID {
			continue
		}
		users := []string{}
		if policy.VPNPeer != "" {
			if email := emails[policy.VPNPeer]; email != "" {
				users = append(users, email)
			}
		} else {
			for _, peer := range server.Peers {
				if email := emails[peer.ID]; email != "" {
					users = append(users, email)
				}
			}
		}
		if len(users) == 0 {
			continue
		}
		rule := map[string]any{"type": "field", "outboundTag": outboundTag(policy.Channel)}
		if protocol == "socks" || protocol == "http" {
			// These inbounds authenticate users but do not attach an Xray email
			// to requests. Validation permits only one enabled peer.
			rule["inboundTag"] = []string{"xray-in"}
		} else {
			rule["user"] = users
		}
		if policy.Protocol != "" && policy.Protocol != "any" {
			rule["network"] = policy.Protocol
		}
		if policy.DstPort != "" {
			rule["port"] = policy.DstPort
		}
		if policy.DstIP != "" {
			rule["ip"] = []string{policy.DstIP}
		}
		if len(policy.Domains) > 0 {
			domains := make([]string, 0, len(policy.Domains))
			for _, domain := range policy.Domains {
				domains = append(domains, "domain:"+strings.Trim(strings.ToLower(domain), "."))
			}
			rule["domain"] = domains
		}
		rules = append(rules, rule)
	}
	rules = append(rules, defaultRules...)
	inboundTag := "xray-in"
	if protocol == "reality" {
		inboundTag = "reality-in"
	}
	inbound := map[string]any{"tag": inboundTag, "listen": "0.0.0.0", "port": server.Port}
	switch protocol {
	case "reality":
		inbound["protocol"] = "vless"
		inbound["settings"] = map[string]any{"clients": clients, "decryption": "none"}
		inbound["streamSettings"] = map[string]any{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{
				"show": xr.Show, "dest": xr.Destination, "xver": 0,
				"serverNames": xr.ServerNames, "privateKey": xr.PrivateKey, "shortIds": xr.ShortIDs,
			},
		}
	case "vmess":
		inbound["protocol"] = "vmess"
		inbound["settings"] = map[string]any{"clients": clients}
		inbound["streamSettings"] = map[string]any{"network": "tcp"}
	case "vless", "trojan":
		inbound["protocol"] = protocol
		settings := map[string]any{"clients": clients}
		if protocol == "vless" {
			settings["decryption"] = "none"
		}
		inbound["settings"] = settings
		inbound["streamSettings"] = map[string]any{
			"network": "tcp", "security": "tls", "tlsSettings": map[string]any{
				"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}},
			},
		}
	case "shadowsocks":
		inbound["protocol"] = "shadowsocks"
		settings := map[string]any{"method": xr.Method, "network": "tcp"}
		if len(clients) > 0 {
			settings["password"] = clients[0].(map[string]any)["password"]
			settings["email"] = clients[0].(map[string]any)["email"]
		}
		inbound["settings"] = settings
	case "socks":
		inbound["protocol"] = "socks"
		inbound["listen"] = xr.Listen
		inbound["settings"] = map[string]any{"auth": "password", "users": clients, "udp": false}
	case "http":
		inbound["protocol"] = "http"
		inbound["listen"] = xr.Listen
		inbound["settings"] = map[string]any{"users": clients, "allowTransparent": false}
	case "wireguard":
		inbound["protocol"] = "wireguard"
		settings := map[string]any{"secretKey": xr.WGPrivateKey, "peers": clients}
		if xr.MTU != 0 {
			settings["mtu"] = xr.MTU
		}
		inbound["settings"] = settings
	case "hysteria":
		inbound["protocol"] = "hysteria"
		inbound["settings"] = map[string]any{"version": 2, "users": clients}
		inbound["streamSettings"] = map[string]any{
			"method": "hysteria", "security": "tls",
			"hysteriaSettings": map[string]any{"version": 2},
			"tlsSettings": map[string]any{
				"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}},
			},
		}
	default:
		return nil, fmt.Errorf("неподдерживаемый серверный протокол Xray %q", protocol)
	}
	doc := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{inbound},
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	return append(data, '\n'), err
}

func renderXrayUnit(server config.VPNServer, conf string) string {
	return `[Unit]
Description=netOS: Xray server ` + server.Name + `
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/xray run -test -config ` + conf + `
ExecStart=/usr/local/bin/xray run -config ` + conf + `
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`
}

func (s *Subsystem) applyXray(ctx context.Context, cfg *config.Config, server config.VPNServer, wasOwned bool) (created bool, retErr error) {
	confPath, unitPath := s.xrayPaths(server)
	certDir := filepath.Join(s.StateDir, fmt.Sprintf("xray-srv%d-tls", server.Index))
	_, statErr := os.Stat(unitPath)
	existed := statErr == nil
	if existed && !wasOwned {
		return false, fmt.Errorf("служба %s уже существует и не принадлежит netOS", xrayUnitName(server))
	}
	snapshots, err := capturePaths(confPath, unitPath, certDir)
	if err != nil {
		return false, err
	}
	mutated := false
	defer func() {
		if retErr == nil || !mutated {
			return
		}
		if !existed {
			s.cleanupXray(context.Background(), server)
			return
		}
		if err := restorePaths(snapshots); err != nil {
			retErr = fmt.Errorf("%v; восстановление Xray: %w", retErr, err)
			return
		}
		_, _ = s.Runner.Run(context.Background(), "systemctl", "daemon-reload")
		_, _ = s.Runner.Run(context.Background(), "systemctl", "restart", xrayUnitName(server))
	}()
	xr, err := server.XrayConfig()
	if err != nil {
		return false, err
	}
	if xr.Protocol == "vless" || xr.Protocol == "trojan" || xr.Protocol == "hysteria" {
		mutated = true
		names := []string{}
		if xr.PublicEndpoint != "" {
			if host, _, splitErr := net.SplitHostPort(xr.PublicEndpoint); splitErr == nil {
				names = append(names, host)
			}
		}
		if _, _, _, err := tlsutil.EnsureSelfSignedForNames(certDir, cfg.System.Hostname, names...); err != nil {
			return false, fmt.Errorf("сертификат Xray: %w", err)
		}
	}
	conf, err := renderXrayWithTLS(server, cfg, filepath.Join(certDir, "panel.crt"), filepath.Join(certDir, "panel.key"))
	if err != nil {
		return false, err
	}
	candidate := strings.TrimSuffix(confPath, filepath.Ext(confPath)) + ".candidate.json"
	if err := writeFile(candidate, conf, 0o600); err != nil {
		return false, err
	}
	defer os.Remove(candidate)
	if _, err := s.Runner.Run(ctx, "/usr/local/bin/xray", "run", "-test", "-config", candidate); err != nil {
		return false, fmt.Errorf("проверка конфигурации Xray: %w", err)
	}
	unit := []byte(renderXrayUnit(server, confPath))
	changed := system.FileChanged(confPath, conf) || system.FileChanged(unitPath, unit)
	if err := os.Rename(candidate, confPath); err != nil {
		return false, err
	}
	mutated = true
	if err := os.Chmod(confPath, 0o600); err != nil {
		return false, err
	}
	if err := writeFile(unitPath, unit, 0o644); err != nil {
		return false, err
	}
	unitName := xrayUnitName(server)
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return false, err
		}
	}
	if err := s.ensureUnitEnabled(ctx, unitName); err != nil {
		return false, err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unitName)
	if changed || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
			return false, fmt.Errorf("запуск сервера Xray: %w", err)
		}
	}
	return !existed, nil
}

func (s *Subsystem) cleanupXray(ctx context.Context, server config.VPNServer) {
	unitName := xrayUnitName(server)
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", unitName)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", unitName)
	conf, unit := s.xrayPaths(server)
	candidate := strings.TrimSuffix(conf, filepath.Ext(conf)) + ".candidate.json"
	for _, path := range []string{conf, candidate, unit} {
		_ = os.Remove(path)
	}
	_ = os.RemoveAll(filepath.Join(s.StateDir, fmt.Sprintf("xray-srv%d-tls", server.Index)))
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}

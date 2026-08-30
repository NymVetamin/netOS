package vpnservers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/system"
)

func xrayUnitName(server config.VPNServer) string {
	return fmt.Sprintf("netos-xray-srv%d.service", server.Index)
}

func (s *Subsystem) xrayPaths(server config.VPNServer) (string, string) {
	return filepath.Join(s.StateDir, fmt.Sprintf("xray-srv%d.json", server.Index)),
		filepath.Join(s.UnitDir, xrayUnitName(server))
}

func RenderXray(server config.VPNServer, cfg *config.Config) ([]byte, error) {
	xr, err := server.XrayConfig()
	if err != nil {
		return nil, err
	}
	clients := make([]any, 0, len(server.Peers))
	outbounds := []any{map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}}}
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
					"tag": tag, "protocol": "freedom", "settings": map[string]any{},
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
		client := map[string]any{"id": peer.Credentials["uuid"], "email": email}
		if xr.Flow != "" {
			client["flow"] = xr.Flow
		}
		clients = append(clients, client)
		emails[peer.ID] = email
		channelID := peer.Channel
		if channelID == "" {
			channelID = server.DefaultChannel
		}
		defaultRules = append(defaultRules, map[string]any{"type": "field", "user": []string{email}, "outboundTag": outboundTag(channelID)})
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
		rule := map[string]any{"type": "field", "user": users, "outboundTag": outboundTag(policy.Channel)}
		if policy.Protocol != "" && policy.Protocol != "any" {
			rule["network"] = policy.Protocol
		}
		if policy.DstPort != "" {
			rule["port"] = policy.DstPort
		}
		if policy.DstIP != "" {
			rule["ip"] = []string{policy.DstIP}
		}
		rules = append(rules, rule)
	}
	rules = append(rules, defaultRules...)
	doc := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "reality-in", "listen": "0.0.0.0", "port": server.Port, "protocol": "vless",
			"settings": map[string]any{"clients": clients, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"show": xr.Show, "dest": xr.Destination, "xver": 0,
					"serverNames": xr.ServerNames, "privateKey": xr.PrivateKey, "shortIds": xr.ShortIDs,
				},
			},
		}},
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	return append(data, '\n'), err
}

func renderXrayUnit(server config.VPNServer, conf string) string {
	return `[Unit]
Description=netOS: Xray Reality server ` + server.Name + `
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

func (s *Subsystem) applyXray(ctx context.Context, cfg *config.Config, server config.VPNServer) (bool, error) {
	confPath, unitPath := s.xrayPaths(server)
	_, statErr := os.Stat(unitPath)
	existed := statErr == nil
	conf, err := RenderXray(server, cfg)
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
	if _, err := s.Runner.Run(ctx, "systemctl", "enable", unitName); err != nil {
		return false, err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unitName)
	if changed || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
			s.cleanupXray(ctx, server)
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
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}

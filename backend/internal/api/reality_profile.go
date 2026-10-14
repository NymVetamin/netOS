package api

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

func realityClientLink(server config.VPNServer, peer config.VPNPeer) (string, error) {
	cfg, err := server.XrayConfig()
	if err != nil {
		return "", fmt.Errorf("Не удалось прочитать настройки Reality-сервера")
	}
	public, err := xrayPublicKey(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("Сначала создайте корректный ключ Reality-сервера")
	}
	endpoint := strings.TrimSpace(cfg.PublicEndpoint)
	host, port, err := net.SplitHostPort(endpoint)
	n, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || n < 1 || n > 65535 || strings.ContainsAny(host, "/?#@ \t\r\n") {
		return "", fmt.Errorf("Укажите публичный адрес Reality-сервера в формате host:port")
	}
	if len(cfg.ServerNames) == 0 || strings.TrimSpace(cfg.ServerNames[0]) == "" {
		return "", fmt.Errorf("Укажите SNI Reality-сервера")
	}
	if len(cfg.ShortIDs) == 0 || cfg.ShortIDs[0] == "" {
		return "", fmt.Errorf("Создайте Short ID Reality-сервера")
	}
	uuid := peer.Credentials["uuid"]
	if uuid == "" {
		return "", fmt.Errorf("Создайте UUID устройства Reality")
	}
	query := url.Values{"encryption": {"none"}, "security": {"reality"}, "sni": {cfg.ServerNames[0]}, "fp": {"chrome"}, "pbk": {public}, "sid": {cfg.ShortIDs[0]}, "type": {"tcp"}}
	if cfg.Flow != "" {
		query.Set("flow", cfg.Flow)
	}
	name := peer.Name
	if name == "" {
		name = peer.ID
	}
	link := url.URL{Scheme: "vless", User: url.User(uuid), Host: net.JoinHostPort(host, port), RawQuery: query.Encode(), Fragment: name}
	return link.String(), nil
}

func (s *Server) handleRealityClientProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if roleOf(r) != "admin" {
		writeError(w, http.StatusForbidden, "Доступно только администратору")
		return
	}
	for _, server := range s.currentDraft().VPNServers {
		if server.ID != r.PathValue("id") || server.Type != "xray" {
			continue
		}
		cfg, err := server.XrayConfig()
		if err != nil || (cfg.Protocol != "" && cfg.Protocol != "reality") {
			continue
		}
		for _, peer := range server.Peers {
			if peer.ID != r.PathValue("peer") {
				continue
			}
			link, err := realityClientLink(server, peer)
			if err != nil {
				writeError(w, http.StatusConflict, "%s", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"link": link})
			return
		}
	}
	writeError(w, http.StatusNotFound, "Устройство Reality не найдено")
}

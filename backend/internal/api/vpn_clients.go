package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

// Secrets are returned only on explicit administrator request, never in config
// or monitoring responses. Existing clients without a retained key stay valid.
func (s *Server) handleVPNClientProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if roleOf(r) != "admin" {
		writeError(w, http.StatusForbidden, "доступно только администратору")
		return
	}
	for _, server := range s.currentDraft().VPNServers {
		if server.ID != r.PathValue("id") || server.Type != "wireguard" {
			continue
		}
		for _, peer := range server.Peers {
			if peer.ID != r.PathValue("peer") {
				continue
			}
			private := peer.Credentials["private_key"]
			public, err := wireGuardPublicKey(private)
			if err != nil || public != peer.Credentials["public_key"] {
				writeError(w, http.StatusConflict, "Закрытый ключ этого профиля не сохранён или не соответствует публичному. Импортируйте прежний .conf или перевыпустите профиль.")
				return
			}
			serverPrivate, _ := server.Config["private_key"].(string)
			serverPublic, err := wireGuardPublicKey(serverPrivate)
			if err != nil {
				writeError(w, http.StatusConflict, "Сначала настройте ключ WireGuard-сервера")
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"privateKey": private, "publicKey": public, "serverPublicKey": serverPublic, "presharedKey": peer.Credentials["preshared_key"]})
			return
		}
	}
	writeError(w, http.StatusNotFound, "Клиент WireGuard не найден")
}

type vpnClientStatus struct {
	ID            string `json:"id"`
	PublicKey     string `json:"public_key"`
	State         string `json:"state"`
	Endpoint      string `json:"endpoint"`
	LastHandshake int64  `json:"last_handshake"`
	Received      uint64 `json:"received"`
	Sent          uint64 `json:"sent"`
}

func (s *Server) handleVPNClientStatus(w http.ResponseWriter, r *http.Request) {
	if roleOf(r) != "admin" {
		writeError(w, http.StatusForbidden, "доступно только администратору")
		return
	}
	// Use applied configuration: a draft must never masquerade as live state.
	for _, server := range s.Engine.Current().VPNServers {
		if server.ID == r.PathValue("id") && server.Type == "wireguard" {
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
			defer cancel()
			writeJSON(w, http.StatusOK, s.wireGuardClients(ctx, server, time.Now()))
			return
		}
	}
	writeJSON(w, http.StatusOK, []vpnClientStatus{})
}

func (s *Server) wireGuardClients(ctx context.Context, server config.VPNServer, now time.Time) []vpnClientStatus {
	rows := map[string]*vpnClientStatus{}
	seen := map[string]int{}
	available := server.Enabled && s.Collector != nil && s.Collector.Runner != nil
	// Select only public telemetry. `dump` also contains private and preshared keys.
	for fieldIndex, field := range []string{"latest-handshakes", "endpoints", "transfer"} {
		if !available {
			break
		}
		out, err := s.Collector.Runner.Run(ctx, "wg", "show", vpnservers.InterfaceName(server), field)
		if err != nil {
			available = false
			break
		}
		for _, line := range strings.Split(out, "\n") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			seen[parts[0]] |= 1 << fieldIndex
			row := rows[parts[0]]
			if row == nil {
				row = &vpnClientStatus{}
				rows[parts[0]] = row
			}
			switch field {
			case "latest-handshakes":
				row.LastHandshake, err = strconv.ParseInt(parts[1], 10, 64)
				if err != nil || row.LastHandshake < 0 {
					available = false
				}
			case "endpoints":
				if parts[1] != "(none)" {
					row.Endpoint = parts[1]
				}
			case "transfer":
				if len(parts) != 3 {
					available = false
					continue
				}
				row.Received, err = strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					available = false
				}
				row.Sent, err = strconv.ParseUint(parts[2], 10, 64)
				if err != nil {
					available = false
				}
			}
		}
	}
	result := make([]vpnClientStatus, 0, len(server.Peers))
	for _, peer := range server.Peers {
		row := vpnClientStatus{ID: peer.ID, PublicKey: peer.Credentials["public_key"], State: "unknown"}
		switch {
		case !server.Enabled:
			row.State = "server_disabled"
		case !peer.Enabled:
			row.State = "disabled"
		case available:
			if live := rows[row.PublicKey]; live != nil && seen[row.PublicKey] == 7 {
				row.Endpoint, row.LastHandshake, row.Received, row.Sent = live.Endpoint, live.LastHandshake, live.Received, live.Sent
				row.State = "never"
				if row.LastHandshake > 0 {
					row.State = "idle"
					age := now.Unix() - row.LastHandshake
					if age >= 0 && age < 180 {
						row.State = "recent"
					}
				}
			}
		}
		result = append(result, row)
	}
	return result
}

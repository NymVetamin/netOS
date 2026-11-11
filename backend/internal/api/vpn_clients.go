package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/amneziawg"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

// Secrets are returned only on explicit administrator request, never in config
// or monitoring responses. Existing clients without a retained key stay valid.
func (s *Server) handleVPNClientProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !may(r, "vpn-servers", true) {
		writeError(w, http.StatusForbidden, "доступно только администратору")
		return
	}
	for _, server := range s.requestConfig(r).VPNServers {
		if server.ID != r.PathValue("id") || !config.IsWireGuardType(server.Type) {
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
			profile := map[string]string{"privateKey": private, "publicKey": public, "serverPublicKey": serverPublic, "presharedKey": peer.Credentials["preshared_key"]}
			if server.Type == "amneziawg" {
				wg, err := server.WireGuardConfig()
				if err != nil {
					writeError(w, http.StatusConflict, "Некорректная конфигурация AmneziaWG")
					return
				}
				parameters, err := config.WireGuardNativeOptions(server.Type, wg.Amnezia)
				if err != nil {
					writeError(w, http.StatusConflict, "Некорректные параметры AmneziaWG")
					return
				}
				profile["amneziaParameters"] = parameters
			}
			writeJSON(w, http.StatusOK, profile)
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
	LastSeen      int64  `json:"last_seen"`
	TrafficKnown  bool   `json:"traffic_known"`
	Received      uint64 `json:"received"`
	Sent          uint64 `json:"sent"`
}

func (s *Server) handleVPNClientStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !anySection(r, false, "clients", "map", "vpn-servers", "dashboard") {
		writeError(w, http.StatusForbidden, "доступно только администратору")
		return
	}
	// Use applied configuration: a draft must never masquerade as live state.
	for _, server := range s.Engine.Current().VPNServers {
		if server.ID == r.PathValue("id") {
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
			defer cancel()
			writeJSON(w, http.StatusOK, s.vpnClients(ctx, server))
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
	fields := []string{"latest-handshakes", "endpoints", "transfer"}
	if server.Type == "amneziawg" {
		fields = []string{"telemetry"}
	}
	for fieldIndex, field := range fields {
		if !available {
			break
		}
		out, err := amneziawg.WireGuardControl(ctx, s.Collector.Runner, server.Type, "show", vpnservers.InterfaceName(server), field)
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
			case "telemetry":
				if len(parts) != 5 {
					available = false
					continue
				}
				seen[parts[0]] = 7
				row.LastHandshake, err = strconv.ParseInt(parts[1], 10, 64)
				if err != nil || row.LastHandshake < 0 {
					available = false
				}
				if parts[2] != "(none)" {
					row.Endpoint = parts[2]
				}
				row.Received, err = strconv.ParseUint(parts[3], 10, 64)
				if err != nil {
					available = false
				}
				row.Sent, err = strconv.ParseUint(parts[4], 10, 64)
				if err != nil {
					available = false
				}
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
				row.TrafficKnown = true
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

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/vpnpki"
)

func (s *Server) handleOCClientCertificate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if roleOf(r) != "admin" {
		writeError(w, http.StatusForbidden, "доступно только администратору")
		return
	}
	if s.PKI == nil {
		writeError(w, http.StatusServiceUnavailable, "хранилище сертификатов недоступно")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	var result any
	status := http.StatusOK
	err := s.Engine.Maintain(ctx, func(cfg *config.Config) error {
		var server *config.VPNServer
		var peer *config.VPNPeer
		for i := range cfg.VPNServers {
			item := &cfg.VPNServers[i]
			if item.ID == r.PathValue("id") && item.Type == "ocserv" {
				server = item
				break
			}
		}
		if server != nil {
			for i := range server.Peers {
				if server.Peers[i].ID == r.PathValue("peer") {
					peer = &server.Peers[i]
					break
				}
			}
		}
		if server == nil || peer == nil || server.OcservAuthMode() == "password" {
			if r.Method == http.MethodGet && r.PathValue("action") == "" {
				result = map[string]any{"pending": true}
				return nil
			}
			status = http.StatusConflict
			return fmt.Errorf("Сначала примените настройки устройства и авторизацию по сертификату")
		}
		action := r.PathValue("action")
		if r.Method == http.MethodPost {
			var mutationErr error
			switch action {
			case "revoke":
				mutationErr = s.PKI.Revoke(*server, peer.ID)
			case "reissue":
				mutationErr = s.PKI.Reissue(ctx, *server, *peer)
			default:
				status = http.StatusNotFound
				return fmt.Errorf("неизвестное действие")
			}
			// Restart this server to invalidate session cookies and load the CRL
			// synchronously. A HUP alone acknowledges neither of those operations.
			if server.Enabled {
				unit := fmt.Sprintf("netos-ocserv-srv%d.service", server.Index)
				if mutationErr != nil {
					_, stopErr := s.PKI.Runner.Run(ctx, "systemctl", "stop", unit)
					if stopErr != nil {
						return fmt.Errorf("не удалось обновить сертификат и остановить OpenConnect: %v; ошибка сертификата: %w", stopErr, mutationErr)
					}
					return fmt.Errorf("не удалось обновить сертификат; сервер остановлен для защиты доступа: %w", mutationErr)
				}
				if _, err := s.PKI.Runner.Run(ctx, "systemctl", "restart", unit); err != nil {
					_, _ = s.PKI.Runner.Run(ctx, "systemctl", "stop", unit)
					return fmt.Errorf("сертификат обновлён, но OpenConnect не запустился: %w", err)
				}
			}
			if mutationErr != nil {
				return mutationErr
			}
		} else if action != "" && action != "password" && action != "download" {
			status = http.StatusNotFound
			return fmt.Errorf("неизвестное действие")
		}
		client, err := s.PKI.Get(server.ID, peer.ID)
		if err != nil {
			if !os.IsNotExist(err) && !errors.Is(err, vpnpki.ErrNotIssued) {
				return fmt.Errorf("не удалось прочитать хранилище сертификатов: %w", err)
			}
			if r.Method == http.MethodGet && action == "" {
				result = map[string]any{"pending": true}
				return nil
			}
			status = http.StatusConflict
			return fmt.Errorf("Сертификат недоступен; примените настройки или перевыпустите профиль")
		}
		result = map[string]any{"serial": client.Serial, "expires": client.Expires, "revoked": client.Revoked, "username": server.OcservUsername(*peer)}
		if r.Method == http.MethodGet && (action == "password" || action == "download") {
			if client.Revoked || time.Now().After(client.Expires) {
				status = http.StatusConflict
				return fmt.Errorf("Сертификат отозван или истёк; перевыпустите профиль")
			}
			if action == "password" {
				result = map[string]string{"password": client.Password}
			} else {
				result = client.P12
			}
		}
		return nil
	})
	if err != nil {
		if status == http.StatusOK {
			status = http.StatusInternalServerError
		}
		writeError(w, status, "%s", err.Error())
		return
	}
	if data, ok := result.([]byte); ok {
		w.Header().Set("Content-Type", "application/x-pkcs12")
		w.Header().Set("Content-Disposition", `attachment; filename="openconnect-client.p12"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}
	writeJSON(w, status, result)
}

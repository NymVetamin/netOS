package api

import (
	"github.com/netos-router/netos/internal/subsys/socks"
	"github.com/netos-router/netos/internal/system"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleSocksCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !may(r, "services", true) {
		writeError(w, http.StatusForbidden, "доступно только администратору")
		return
	}
	p := s.requestConfig(r).Socks
	writeJSON(w, http.StatusOK, map[string]string{"username": p.Username, "password": p.Password})
}
func (s *Server) handleSocksStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Engine == nil || s.Engine.Current() == nil {
		writeError(w, http.StatusServiceUnavailable, "состояние SOCKS5 недоступно")
		return
	}
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 5 * time.Second}
	}
	enabled := s.Engine.Current().Socks.Enabled
	active := false
	if enabled {
		out, _ := runner.Run(r.Context(), "systemctl", "is-active", socks.Unit)
		active = strings.TrimSpace(out) == "active"
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled, "running": active})
}

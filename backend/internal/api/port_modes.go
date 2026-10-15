package api

import (
	"github.com/netos-router/netos/internal/ethernet"
	"github.com/netos-router/netos/internal/system"
	"net/http"
	"time"
)

func (s *Server) handlePortModes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Collector == nil {
		writeError(w, 503, "данные портов недоступны")
		return
	}
	stats, err := s.Collector.InterfaceStats()
	if err != nil {
		writeError(w, 500, "%v", err)
		return
	}
	name := r.PathValue("name")
	physical := false
	for _, i := range stats {
		if i.Name == name && i.Physical {
			physical = true
		}
	}
	if !physical {
		writeError(w, 400, "выберите физический порт")
		return
	}
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 5 * time.Second}
	}
	settings, err := ethernet.Read(r.Context(), runner.Run, name)
	if err != nil {
		writeError(w, 503, "%v", err)
		return
	}
	writeJSON(w, 200, settings)
}

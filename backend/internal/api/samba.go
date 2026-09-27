package api

import (
	"net/http"
	"time"

	"github.com/netos-router/netos/internal/subsys/samba"
	"github.com/netos-router/netos/internal/system"
)

func (s *Server) handleStorageDevices(w http.ResponseWriter, r *http.Request) {
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 10 * time.Second}
	}
	devices, err := samba.Devices(r.Context(), runner)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Не удалось прочитать список накопителей: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

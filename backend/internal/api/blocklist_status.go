package api

import (
	"net/http"

	"github.com/netos-router/netos/internal/subsys/services"
)

func (s *Server) handleBlocklistStatus(w http.ResponseWriter, r *http.Request) {
	statuses, err := services.ReadBlocklistStatuses()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось прочитать статус DNS blocklists: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": statuses})
}

package api

import "net/http"

func (s *Server) handleUserPreferences(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ShowHints *bool `json:"show_hints"`
	}
	if err := readJSON(r, &req); err != nil || req.ShowHints == nil {
		writeError(w, http.StatusBadRequest, "укажите, показывать ли подсказки")
		return
	}
	if err := s.Store.SetShowHints(userOf(r), *req.ShowHints); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить настройку подсказок")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"show_hints": *req.ShowHints})
}

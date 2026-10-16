package api

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/netos-router/netos/internal/store"
)

var panelSections = map[string]bool{
	"dashboard": true, "map": true, "clients": true, "network": true, "routing": true,
	"channels": true, "vpn-servers": true, "wifi": true, "storage": true, "traffic": true,
	"services": true, "firewall": true, "components": true, "system": true, "history": true, "diagnostics": true,
}
var panelUsername = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func (s *Server) userPermissions(username string) map[string]string {
	a, err := s.Store.PanelAccess(username)
	if err != nil {
		return nil
	}
	return a.Permissions
}

func (s *Server) handlePanelUsers(w http.ResponseWriter, r *http.Request) {
	if roleOf(r) != "admin" {
		writeError(w, http.StatusForbidden, "управление пользователями доступно только администратору")
		return
	}
	if r.Method == http.MethodGet {
		users, err := s.Store.PanelUsers()
		if err != nil {
			writeError(w, 500, "не удалось загрузить пользователей")
			return
		}
		writeJSON(w, 200, users)
		return
	}
	var req struct {
		store.PanelUser
		Password string `json:"password"`
	}
	remove := r.Method == http.MethodDelete
	if remove {
		req.Username = r.PathValue("username")
	} else if err := readJSON(r, &req); err != nil {
		writeError(w, 400, "некорректные данные пользователя")
		return
	}
	if !panelUsername.MatchString(req.Username) {
		writeError(w, 400, "логин: до 64 латинских букв, цифр и символов . _ -")
		return
	}
	if !remove {
		if req.Role != "admin" && req.Role != "limited" {
			writeError(w, 400, "неизвестная роль")
			return
		}
		for section, level := range req.Permissions {
			if !panelSections[section] || (level != "none" && level != "view" && level != "manage") {
				writeError(w, 400, "неизвестное право доступа")
				return
			}
		}
	}
	if req.Password != "" && (len(req.Password) < 12 || len(req.Password) > 1024) {
		writeError(w, 400, "пароль должен содержать от 12 до 1024 байт")
		return
	}
	var hash string
	if req.Password != "" {
		var err error
		hash, err = HashPassword(req.Password)
		if err != nil {
			writeError(w, 500, "не удалось сохранить пароль")
			return
		}
	}
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	if s.draftApplying {
		writeError(w, 409, "дождитесь завершения применения настроек")
		return
	}
	err := s.Store.SavePanelUser(req.PanelUser, hash, r.Method == http.MethodPost, remove, userOf(r), clientIP(r))
	if err != nil {
		switch {
		case errors.Is(err, store.ErrLastAdmin):
			writeError(w, 409, "%v", err)
		case errors.Is(err, store.ErrNotFound):
			writeError(w, 404, "пользователь не найден")
		default:
			writeError(w, 400, "не удалось сохранить пользователя: проверьте логин и пароль")
		}
		return
	}
	delete(s.privateDrafts, req.Username)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

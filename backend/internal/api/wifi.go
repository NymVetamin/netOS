package api

import (
	"context"
	"errors"
	"net/http"
	"os/exec"
	"time"

	"github.com/netos-router/netos/internal/subsys/wifi"
	"github.com/netos-router/netos/internal/system"
)

func (s *Server) handleWiFiHardware(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	runner := s.StorageRunner
	if runner == nil {
		runner = &system.Exec{Timeout: 5 * time.Second}
	}
	hardware, err := wifi.ReadHardware(ctx, runner, r.URL.Query().Get("country"))
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			writeError(w, 503, "Для поиска радиоустройств нужна утилита iw. Установите компонент Wi-Fi или пакет iw.")
			return
		}
		writeError(w, 503, "%v", err)
		return
	}
	writeJSON(w, 200, hardware)
}

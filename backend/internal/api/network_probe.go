package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var probeHostname = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// A probe accepts one host as an argv element. Never pass user input to a shell.
func (s *Server) handleDiagnosticProbe(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Kind string `json:"kind"`
		Host string `json:"host"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный запрос")
		return
	}
	input.Host = strings.TrimSpace(input.Host)
	if len(input.Host) > 253 || (net.ParseIP(input.Host) == nil && !probeHostname.MatchString(input.Host)) || strings.Contains(input.Host, "..") {
		writeError(w, http.StatusBadRequest, "укажите IP-адрес или имя узла")
		return
	}
	var name string
	var args []string
	switch input.Kind {
	case "ping":
		name, args = "ping", []string{"-n", "-c", "3", "-W", "2", "--", input.Host}
	case "traceroute":
		name, args = "traceroute", []string{"-n", "-m", "12", "-w", "1", "-q", "1", "--", input.Host}
	default:
		writeError(w, http.StatusBadRequest, "неизвестный вид проверки")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if len(output) > 16384 {
		output = output[:16384]
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		writeJSON(w, http.StatusOK, map[string]any{"output": string(output), "success": false, "error": "превышено время ожидания"})
		return
	}
	if errors.Is(err, exec.ErrNotFound) {
		writeError(w, http.StatusServiceUnavailable, "%s не установлен", name)
		return
	}
	result := map[string]any{"output": string(output), "success": err == nil}
	if err != nil {
		result["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, result)
}

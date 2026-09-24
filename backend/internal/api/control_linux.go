package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ControlSocketPath is accessible only to root. The local CLI uses it to
// operate on the daemon's in-memory draft through the same apply handlers as
// the panel, without storing an administrator password on disk.
const ControlSocketPath = "/run/netosd/control.sock"

func (s *Server) startLocalControl() (func(), <-chan error, error) {
	if err := os.MkdirAll(filepath.Dir(ControlSocketPath), 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(filepath.Dir(ControlSocketPath), 0o700); err != nil {
		return nil, nil, err
	}
	if info, err := os.Lstat(ControlSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("control socket path is not a socket: %s", ControlSocketPath)
		}
		if conn, dialErr := net.DialTimeout("unix", ControlSocketPath, 200*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("control socket already has a listener: %s", ControlSocketPath)
		}
		if err := os.Remove(ControlSocketPath); err != nil {
			return nil, nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	ln, err := net.Listen("unix", ControlSocketPath)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(ControlSocketPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(ControlSocketPath)
		return nil, nil, err
	}
	mux := http.NewServeMux()
	root := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, r.WithContext(context.WithValue(r.Context(), ctxUser, "root")))
		}
	}
	mux.HandleFunc("GET /draft", root(func(w http.ResponseWriter, r *http.Request) {
		_, dirty, version := s.draftSnapshot()
		writeJSON(w, http.StatusOK, map[string]any{"dirty": dirty, "draft_version": version})
	}))
	mux.HandleFunc("POST /apply", root(s.handleApply))
	mux.HandleFunc("POST /confirm", root(s.handleConfirm))
	server := &http.Server{
		Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 15 * time.Minute,
		MaxHeaderBytes: 8 << 10,
	}
	done := make(chan error, 1)
	go func() {
		err := server.Serve(ln)
		if err == http.ErrServerClosed {
			err = nil
		}
		done <- err
	}()
	stop := func() {
		_ = server.Close()
		_ = os.Remove(ControlSocketPath)
	}
	return stop, done, nil
}

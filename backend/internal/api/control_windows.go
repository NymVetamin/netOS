package api

const ControlSocketPath = "/run/netosd/control.sock"

// Windows is only a development and test platform for netOS.
func (s *Server) startLocalControl() (func(), <-chan error, error) {
	return func() {}, nil, nil
}

package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

// Package installation is exercised through a fake Runner. Keep Debian's
// temporary daemon-start guard out of the host /usr/sbin directory as well.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "netos-policy-tests-")
	if err != nil {
		panic(err)
	}
	system.PolicyRCPath = filepath.Join(root, "policy-rc.d")
	code := m.Run()
	if err := os.RemoveAll(root); err != nil && code == 0 {
		code = 1
	}
	os.Exit(code)
}

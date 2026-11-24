//go:build !linux

package system

import (
	"context"
	"os/exec"
)

func runManagedCommand(_ context.Context, command func() *exec.Cmd, _ string, _ bool) error {
	return command().Run()
}

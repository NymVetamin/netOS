//go:build !linux

package system

import (
	"context"
	"os/exec"
)

func runPackageCommand(_ context.Context, cmd *exec.Cmd, _ string) error { return cmd.Run() }

func stopGroupOnCancel(*exec.Cmd) {}

//go:build !windows

package manage

import (
	"os"

	"golang.org/x/sys/unix"
)

func tryMaintenanceLock(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

//go:build linux

package api

import (
	"fmt"
	"os"
	"syscall"
)

func dnsFileID(_ *os.File, info os.FileInfo) (string, error) {
	st := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%x:%x", st.Dev, st.Ino), nil
}

package vpnpki

import (
	"os"
	"syscall"
)

func matchesPublishedMetadata(info os.FileInfo, perm os.FileMode) bool {
	stat := info.Sys().(*syscall.Stat_t)
	return info.Mode() == perm && stat.Nlink == 1 &&
		stat.Uid == uint32(os.Geteuid()) && stat.Gid == uint32(os.Getegid())
}

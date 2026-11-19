//go:build !linux

package vpnpki

import (
	"os"
	"runtime"
)

func matchesPublishedMetadata(info os.FileInfo, perm os.FileMode) bool {
	if runtime.GOOS == "windows" {
		return info.Mode()&0200 == perm&0200
	}
	return info.Mode() == perm
}

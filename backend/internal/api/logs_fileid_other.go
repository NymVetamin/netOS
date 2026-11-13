//go:build !linux && !windows

package api

import (
	"fmt"
	"os"
)

func dnsFileID(*os.File, os.FileInfo) (string, error) {
	return "", fmt.Errorf("снимки DNS-файлов не поддерживаются на этой ОС")
}

//go:build windows

package api

import (
	"fmt"
	"os"
	"syscall"
)

func dnsFileID(f *os.File, _ os.FileInfo) (string, error) {
	var st syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &st); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x:%x", st.VolumeSerialNumber, st.FileIndexHigh, st.FileIndexLow), nil
}

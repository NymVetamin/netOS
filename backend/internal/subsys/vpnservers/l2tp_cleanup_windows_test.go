package vpnservers

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestL2TPCleanupWindowsWriteFailure(t *testing.T) {
	checkL2TPCleanupWriteFailure(t, func(path string) func() {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatal(err)
		}
		closed := false
		close := func() {
			if !closed {
				closed = true
				if err := windows.CloseHandle(h); err != nil {
					t.Error(err)
				}
			}
		}
		t.Cleanup(close)
		return close
	})
}

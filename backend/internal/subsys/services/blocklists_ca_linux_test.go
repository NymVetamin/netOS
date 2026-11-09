package services

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Устройство и FIFO проверяются на настоящей ОС: /dev/zero читался бы до
// исчерпания памяти, а открытие FIFO без писателя не завершилось бы вовсе.
func TestBlocklistCARejectsDeviceAndFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "ca.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/dev/zero", fifo} {
		done := make(chan error, 1)
		go func() {
			_, err := readBlocklistCA(path)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "не является обычным файлом") {
				t.Fatalf("%s: %v", path, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: чтение не завершилось", path)
		}
	}
}

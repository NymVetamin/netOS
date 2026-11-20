package system

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAtomicReplaceFIFO(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "fifo"
		if symlink {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			fifo := filepath.Join(dir, "pipe")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			path := fifo
			if symlink {
				path = filepath.Join(dir, "link")
				if err := os.Symlink(fifo, path); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan struct{})
			var changed bool
			var err error
			go func() {
				changed, err = WriteFileAtomicIfChanged(path, []byte("ready"), 0o640)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("write blocked on FIFO without a writer")
			}
			if err != nil || !changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
				t.Fatalf("replacement: %v %v", info, err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "ready" {
				t.Fatalf("data=%q err=%v", data, err)
			}
			if symlink {
				info, err := os.Lstat(fifo)
				if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
					t.Fatalf("link target: %v %v", info, err)
				}
			}
			if changed, err := WriteFileAtomicIfChanged(path, data, 0o640); err != nil || changed {
				t.Fatalf("repeat: changed=%v err=%v", changed, err)
			}
		})
	}
}

package api

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/runtime"
	"golang.org/x/sys/unix"
)

func TestPortModesSkipsInterfaceCounters(t *testing.T) {
	root := t.TempDir()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for _, name := range []string{"eth0", "eth1"} {
		base := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Join(base, "device"), 0700); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"ifindex", "flags"} {
			if err := os.WriteFile(filepath.Join(base, file), []byte("1"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := unix.InotifyAddWatch(fd, filepath.Join(base, "flags"), unix.IN_OPEN); err != nil {
			t.Fatal(err)
		}
	}
	run := &portModeRunner{}
	c := runtime.NewCollector(run, "")
	c.SysClassNet = root
	s := &Server{Collector: c, StorageRunner: run}
	req := httptest.NewRequest("GET", "/api/interfaces/eth0/modes", nil)
	req.SetPathValue("name", "eth0")
	w := httptest.NewRecorder()
	s.handlePortModes(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var events [4096]byte
	if n, err := unix.Read(fd, events[:]); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("port mode request opened interface flags: event bytes=%d, err=%v", n, err)
	}
}

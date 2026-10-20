//go:build !windows

package runtime

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDNSFileTailRotationDrainsOldAndReadsNewStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte("historical\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var tail dnsFileTail
	defer tail.close()
	if lines, err := tail.read(path); err != nil || len(lines) != 0 {
		t.Fatalf("initial history replayed: %v %v", lines, err)
	}
	appendLog := func(text string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(text)
		if closeErr := f.Close(); err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
	}
	appendLog("before\npart")
	lines, err := tail.read(path)
	if err != nil || !reflect.DeepEqual(lines, []string{"before"}) {
		t.Fatalf("%v %v", lines, err)
	}
	appendLog("ial\nlast-old\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("first-new\nsecond-new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err = tail.read(path)
	if err != nil || !reflect.DeepEqual(lines, []string{"partial", "last-old"}) {
		t.Fatalf("old descriptor lost: %v %v", lines, err)
	}
	lines, err = tail.read(path)
	if err != nil || !reflect.DeepEqual(lines, []string{"first-new", "second-new"}) {
		t.Fatalf("new file start lost: %v %v", lines, err)
	}
	if lines, err = tail.read(path); err != nil || len(lines) != 0 {
		t.Fatalf("duplicates: %v %v", lines, err)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendLog("short\n")
	if lines, err = tail.read(path); err != nil || !reflect.DeepEqual(lines, []string{"short"}) {
		t.Fatalf("external truncation: %v %v", lines, err)
	}
}

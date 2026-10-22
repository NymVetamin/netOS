package api

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFilesystemUsage(t *testing.T) {
	dir := t.TempDir()
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		t.Fatal(err)
	}
	total, used := filesystemUsage(dir)
	if total == nil || used == nil || *total != stat.Blocks*uint64(stat.Bsize) || *used > *total {
		t.Fatalf("invalid filesystem usage: total=%v used=%v", total, used)
	}
	if total, used := filesystemUsage(filepath.Join(dir, "missing")); total != nil || used != nil {
		t.Fatal("missing filesystem must not report zero usage")
	}
	if total, used := filesystemUsage(dir); total == nil || used == nil {
		t.Fatal("reading must recover after failure")
	}
}

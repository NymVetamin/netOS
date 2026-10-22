package api

import "golang.org/x/sys/unix"

// Read the root filesystem directly; no disk inventory or external process.
func filesystemUsage(path string) (total, used *uint64) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil || stat.Blocks == 0 || stat.Bsize <= 0 || stat.Bfree > stat.Blocks {
		return nil, nil
	}
	t := stat.Blocks * uint64(stat.Bsize)
	u := (stat.Blocks - stat.Bfree) * uint64(stat.Bsize)
	return &t, &u
}

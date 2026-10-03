package store

import (
	"errors"
	"syscall"
)

// IsStorageFull recognizes both a direct filesystem ENOSPC and SQLite's
// SQLITE_FULL (including extended result codes). SQLite can report the latter
// while committing a session to its WAL, without exposing the underlying
// filesystem error to the caller.
func IsStorageFull(err error) bool {
	if errors.Is(err, syscall.ENOSPC) {
		return true
	}
	var sqliteError interface{ Code() int }
	return errors.As(err, &sqliteError) && sqliteError.Code()&0xff == 13
}

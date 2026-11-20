package system

import "golang.org/x/sys/unix"

// A FIFO or symlink may replace the regular file between Lstat and OpenFile.
const atomicCompareFlags = unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_NOCTTY

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// The private hard link identifies the inode we published even after a crash.
// Every live package operation holds a shared lock on that inode.
func acquireDaemonPolicy() (*os.File, func(), error) {
	path := PolicyRCPath
	owner := path + ".netos-owner"
	for {
		f, err := openPolicyOwner(owner)
		if os.IsNotExist(err) {
			if _, e := os.Lstat(path); e == nil {
				// A concurrent publisher creates owner before path.
				if _, e = os.Lstat(owner); os.IsNotExist(e) {
					return nil, func() {}, nil
				} else if e != nil {
					return nil, nil, e
				}
				continue
			} else if !os.IsNotExist(e) {
				return nil, nil, e
			}
			err = publishFileAtomic(owner, []byte(daemonPolicyScript), 0755, os.Link)
			if err == nil || os.IsExist(err) {
				continue
			}
		}
		if err != nil {
			return nil, nil, err
		}
		if err = unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
			f.Close()
			return nil, nil, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		current, err := os.Lstat(owner)
		if os.IsNotExist(err) || (err == nil && !os.SameFile(current, info)) {
			f.Close()
			continue // last release removed this inode while we waited
		}
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		if !validPolicyOwner(f, info) {
			f.Close()
			if _, err := os.Lstat(path); err == nil {
				return nil, func() {}, nil // administrator edited the published file
			}
			return nil, nil, fmt.Errorf("неизвестный файл учёта политики %s", owner)
		}
		// Publish the verified open inode, including if an administrator
		// replaces the private directory entry just before linkat.
		err = unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.AT_FDCWD, path, unix.AT_SYMLINK_FOLLOW)
		if errors.Is(err, unix.EEXIST) {
			// A pre-existing policy always wins. The release below only unlinks
			// path if it is still the same inode as owner.
			err = nil
		}
		if err != nil {
			_ = releasePolicyOwner(f, path, true)
			return nil, nil, err
		}
		return f, sync.OnceFunc(func() { _ = releasePolicyOwner(f, path, true) }), nil
	}
}

func openPolicyOwner(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
}

func validPolicyOwner(f *os.File, info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0755 || info.Size() != int64(len(daemonPolicyScript)) {
		return false
	}
	var data [len(daemonPolicyScript) + 1]byte
	n, err := f.ReadAt(data[:], 0)
	return err == io.EOF && string(data[:n]) == daemonPolicyScript
}

// RecoverDaemonPolicy releases an abandoned policy before startup applies
// configuration. Live holders and unmarked policies from older installations
// cannot be mistaken for a completed operation.
func RecoverDaemonPolicy() error {
	path := PolicyRCPath
	f, err := openPolicyOwner(path + ".netos-owner")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return releasePolicyOwner(f, path, false)
}

func releasePolicyOwner(f *os.File, path string, acquired bool) error {
	defer f.Close()
	// Drop this holder before checking for the last one. Another process may
	// acquire a new shared lock until cleanup obtains the exclusive lock.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		return err
	}
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	valid := validPolicyOwner(f, info)
	if !valid && !acquired {
		return nil
	}
	for _, name := range []string{path, path + ".netos-owner"} {
		// An in-place edit belongs to the administrator. A live holder still
		// knows which private reference it may drop when it releases the file.
		if name == path && !valid {
			continue
		}
		current, err := os.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if os.SameFile(current, info) {
			if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

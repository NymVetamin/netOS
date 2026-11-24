//go:build !linux

package system

import (
	"os"
	"sync"
)

func RecoverDaemonPolicy() error { return nil }

type heldDaemonPolicy struct {
	path  string
	file  os.FileInfo
	users int
}

var daemonPolicyMu sync.Mutex
var activeDaemonPolicy *heldDaemonPolicy

// Called under daemonPolicyMu. The returned release is specific to this inode.
func (p *heldDaemonPolicy) acquire() func() {
	p.users++
	return sync.OnceFunc(func() {
		daemonPolicyMu.Lock()
		defer daemonPolicyMu.Unlock()
		p.users--
		if p.users != 0 || activeDaemonPolicy != p {
			return
		}
		if ownedFileMatches(p.path, []byte(daemonPolicyScript), 0755, p.file) {
			_ = os.Remove(p.path)
		}
		activeDaemonPolicy = nil
	})
}

func acquireDaemonPolicy() (*os.File, func(), error) {
	daemonPolicyMu.Lock()
	defer daemonPolicyMu.Unlock()
	if info, err := os.Lstat(PolicyRCPath); err == nil {
		if p := activeDaemonPolicy; p != nil && p.path == PolicyRCPath && os.SameFile(info, p.file) {
			return nil, p.acquire(), nil
		}
		return nil, func() {}, nil
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	path, content := PolicyRCPath, []byte(daemonPolicyScript)
	var original os.FileInfo
	err := publishFileAtomic(path, content, 0755, func(staged, dest string) error {
		// Stat the open staged file so identity is captured before publication.
		f, err := os.Open(staged)
		if err != nil {
			return err
		}
		defer f.Close()
		original, err = f.Stat()
		if err != nil {
			return err
		}
		return os.Link(staged, dest)
	})
	if os.IsExist(err) {
		return nil, func() {}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	activeDaemonPolicy = &heldDaemonPolicy{path: path, file: original}
	return nil, activeDaemonPolicy.acquire(), nil
}

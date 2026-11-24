package system

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type packageCommandOptionsKey struct{}
type packageCommandOptions struct {
	name    string
	env     []string
	prepare func([]string, []*os.File) ([]string, []*os.File)
}

func (p *Packages) receiptPath(action string, targets []string) string {
	// Only the native runner can observe the actual apt/dpkg transaction.
	if _, ok := p.R.(*Exec); !ok || p.OwnershipDir == "" {
		return ""
	}
	names := slices.Clone(targets)
	slices.Sort(names)
	key := sha256.Sum256([]byte(action + "\x00" + strings.Join(names, "\x00")))
	return filepath.Join(p.OwnershipDir, fmt.Sprintf("interrupted-%x.json", key))
}

func runPackageApt(ctx context.Context, r Runner, args []string) error {
	_, err := r.Run(ctx, "apt-get", args...)
	return err
}

func receiptExists(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// InstallInterrupted includes outstanding dependencies even when all direct
// packages already appear installed in a component readiness snapshot.
func (p *Packages) InstallInterrupted(targets []string) bool {
	exists, err := receiptExists(p.receiptPath("install", targets))
	return exists || err != nil
}

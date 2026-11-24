package system

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type packageCommandOptionsKey struct{}
type upgradeReceiptKey struct{}
type interruptedPackage struct{ Name, Arch, Version string }
type remainingArchive struct {
	interruptedPackage
	Before   string
	UnpackAt int
}
type packageReceipt struct {
	deferredConfigure bool
	Targets           []string
	Started           []interruptedPackage
	Remaining         []remainingArchive
	ConfigureAt       map[string]int `json:",omitempty"`
}

func readPackageReceipt(path string) (packageReceipt, error) {
	var rec packageReceipt
	b, err := os.ReadFile(path)
	if err != nil {
		return rec, err
	}
	if len(b) > 0 && b[0] == '[' {
		err = json.Unmarshal(b, &rec.Started)
	} else {
		err = json.Unmarshal(b, &rec)
	}
	if err == nil && len(rec.Started) == 0 && len(rec.Remaining) == 0 {
		err = errors.New("пустая запись о прерванной установке")
	}
	return rec, err
}

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

func sameTargets(a, b []string) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// InterruptedUpgrade identifies a specific saved order, including progress
// since its previous display, for the existing update token check.
func (p *Packages) InterruptedUpgrade(component string) ([]string, string, error) {
	path := p.receiptPath("upgrade", []string{component})
	if path == "" {
		return nil, "", nil
	}
	rec, err := readPackageReceipt(path)
	if os.IsNotExist(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return rec.Targets, rec.fingerprint(), nil
}

func (rec packageReceipt) fingerprint() string {
	data, _ := json.Marshal(rec) // Contains only strings and slices of strings/records.
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// InstallInterrupted includes outstanding dependencies even when all direct
// packages already appear installed in a component readiness snapshot.
func (p *Packages) InstallInterrupted(targets []string) bool {
	exists, err := receiptExists(p.receiptPath("install", targets))
	return exists || err != nil
}

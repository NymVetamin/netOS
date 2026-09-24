package api

import (
	"fmt"
	"os"
)

var generatedSpacePath = "/var/lib/netos/generated"

// Detect a full generated-files mount before touching the active system. A
// failed write in the middle of Apply also prevents rollback on that mount.
func probeGeneratedSpace() error {
	if _, err := os.Stat(generatedSpacePath); os.IsNotExist(err) {
		return nil // a fresh installation creates the directory during Apply
	} else if err != nil {
		return err
	}
	f, err := os.CreateTemp(generatedSpacePath, ".netos-space-*")
	if err != nil {
		return fmt.Errorf("generated files: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	const reserve = 64 * 1024
	if _, err := f.Write(make([]byte, reserve)); err != nil {
		return fmt.Errorf("generated files: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("generated files: %w", err)
	}
	return nil
}

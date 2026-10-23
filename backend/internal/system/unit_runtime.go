package system

import (
	"bytes"
	"os"
	"strings"
)

// UnitRuntimeChanged permits updating a unit's display description without
// restarting its process. Every other byte remains significant, including
// unknown directives and continuation lines. Callers must still daemon-reload
// when the unit file itself changes.
func UnitRuntimeChanged(path string, wanted []byte) bool {
	before, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	if bytes.Equal(before, wanted) {
		return false
	}
	a, b := strings.Split(string(before), "\n"), strings.Split(string(wanted), "\n")
	if len(a) != len(b) {
		return true
	}
	inUnit := false
	for i, line := range a {
		if line != b[i] {
			if !inUnit || !strings.HasPrefix(line, "Description=") || !strings.HasPrefix(b[i], "Description=") ||
				strings.HasSuffix(strings.TrimSpace(line), "\\") || strings.HasSuffix(strings.TrimSpace(b[i]), "\\") {
				return true
			}
		}
		if strings.HasPrefix(line, "[") {
			inUnit = line == "[Unit]"
		}
	}
	return false
}

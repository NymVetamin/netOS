package services

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingSystemdUnitPhraseMatrix(t *testing.T) {
	for _, message := range []string{
		"Unit demo.service does not exist",
		"Unit demo.service not loaded",
		"no such file",
		"command not found",
		"could not be found",
		"LoadState=not-found",
	} {
		if !missingSystemdUnit(errors.New(message)) {
			t.Fatalf("missing unit phrase rejected: %q", message)
		}
	}
	if missingSystemdUnit(errors.New("permission denied")) {
		t.Fatal("permission failure mistaken for an absent unit")
	}
}

func TestManagedFileWriteHealthValidationAndAbsenceLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "managed.conf")
	content := []byte("option=value\n")
	changed, err := writeManagedFile(path, content, 0o640)
	if err != nil || !changed {
		t.Fatalf("first write changed=%v err=%v", changed, err)
	}
	changed, err = writeManagedFile(path, content, 0o640)
	if err != nil || changed {
		t.Fatalf("idempotent write changed=%v err=%v", changed, err)
	}
	if err := managedFileHealth(path, content, 0o640); err != nil {
		t.Fatalf("healthy managed file=%v", err)
	}
	if err := managedFileModeHealth(path, 0o640, true); err != nil {
		t.Fatalf("healthy managed mode=%v", err)
	}
	if err := generatedAbsent(path); err == nil {
		t.Fatal("present generated file passed absence check")
	}
	if err := os.WriteFile(path, []byte("drift\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := managedFileHealth(path, content, 0o640); err == nil || !strings.Contains(err.Error(), "содержимое") {
		t.Fatalf("content drift error=%v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := generatedAbsent(path); err != nil {
		t.Fatalf("absent generated file=%v", err)
	}
	if err := managedFileModeHealth(path, 0o640, false); err != nil {
		t.Fatalf("optional absent file=%v", err)
	}
	if err := managedFileModeHealth(path, 0o640, true); err == nil {
		t.Fatal("required absent file passed mode health")
	}

	var validationPath string
	err = validateManagedContent(path, content, 0o600, func(candidate string) error {
		validationPath = candidate
		data, readErr := os.ReadFile(candidate)
		if readErr != nil || string(data) != string(content) {
			t.Fatalf("candidate data=%q err=%v", data, readErr)
		}
		return errors.New("validator rejected")
	})
	if err == nil || err.Error() != "validator rejected" {
		t.Fatalf("validator error=%v", err)
	}
	if validationPath == "" {
		t.Fatal("validator was not called")
	}
	if _, err := os.Stat(validationPath); !os.IsNotExist(err) {
		t.Fatalf("validation temp remains: %v", err)
	}
}

func TestUsableResolverContentRequiresRoutableNameserver(t *testing.T) {
	tests := []struct {
		content string
		usable  bool
	}{
		{"nameserver 127.0.0.1\n", false},
		{"nameserver ::1\n", false},
		{"nameserver 0.0.0.0\n", false},
		{"search example.test\n", false},
		{"nameserver invalid\n", false},
		{"nameserver 1.1.1.1\n", true},
		{"nameserver [2001:4860:4860::8888]\n", true},
	}
	for _, tc := range tests {
		if got := usableResolverContent([]byte(tc.content)); got != tc.usable {
			t.Fatalf("usableResolverContent(%q)=%v want %v", tc.content, got, tc.usable)
		}
	}
}

func TestDnsmasqLeasePathUsesManagedRuntimeFile(t *testing.T) {
	if got := (&Dnsmasq{}).LeasePath(); got != dnsmasqLeasePath || got == "" {
		t.Fatalf("LeasePath=%q managed=%q", got, dnsmasqLeasePath)
	}
}

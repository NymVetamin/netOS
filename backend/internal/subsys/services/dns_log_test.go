package services

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSLogCopyTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := rotateDNSLog(path, 16, nil); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for n := 0; n < 5; n++ {
		text := strings.Repeat(string(rune('a'+n)), 16)
		if _, err := writer.WriteString(text[:8]); err != nil {
			t.Fatal(err)
		}
		if err := rotateDNSLog(path, 16, nil); err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(path)
		if info.Size() != 8 {
			t.Fatal("rotated below threshold")
		}
		if _, err := writer.WriteString(text[8:]); err != nil {
			t.Fatal(err)
		}
		if err := rotateDNSLog(path, 16, nil); err != nil {
			t.Fatal(err)
		}
		info, _ = os.Stat(path)
		if info.Size() != 0 {
			t.Fatal("live log not truncated")
		}
		got, _ := os.ReadFile(path + ".1")
		if string(got) != text {
			t.Fatalf("archive = %q", got)
		}
	}
	for n, want := range []string{"eeeeeeeeeeeeeeee", "dddddddddddddddd", "cccccccccccccccc"} {
		got, err := os.ReadFile(path + "." + string(rune('1'+n)))
		if err != nil || string(got) != want {
			t.Fatalf("generation %d: %q %v", n, got, err)
		}
	}
	files, _ := os.ReadDir(filepath.Dir(path))
	if len(files) != 4 {
		t.Fatalf("unbounded generations: %d", len(files))
	}
}

func TestDNSLogReopenFailureAndRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, _ := os.Stat(path)
	failure := errors.New("signal failed")
	if err := rotateDNSLog(path, 8, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("signal failure hidden: %v", err)
	}
	current, _ := os.Stat(path)
	if !os.SameFile(original, current) {
		t.Fatal("failed reopen abandoned original descriptor")
	}
	if err := rotateDNSLog(path, 8, func() error {
		got, err := os.ReadFile(path + ".1")
		if err != nil || string(got) != "original\n" {
			t.Fatalf("old log lost: %q %v", got, err)
		}
		return os.WriteFile(path, []byte("new\n"), 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new\n" {
		t.Fatal("reopened log lost")
	}
}

func TestDNSLogCopyBoundedAndFailurePreservesSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 100)+"last"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Force archive creation to fail after its old generation was moved.
	if err := os.Mkdir(path+".1", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".2", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".3", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".3/block", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rotateDNSLog(path, 4, nil); err == nil {
		t.Fatal("expected archive failure")
	}
	info, _ := os.Stat(path)
	if info.Size() != 104 {
		t.Fatal("source truncated on failure")
	}
	for _, suffix := range []string{".1", ".2", ".3/block", ".3"} {
		if err := os.Remove(path + suffix); err != nil {
			t.Fatal(err)
		}
	}
	if err := rotateDNSLog(path, 4, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path + ".1")
	if string(got) != "last" {
		t.Fatalf("oversized log copy: %q", got)
	}
}

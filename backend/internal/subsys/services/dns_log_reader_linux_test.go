package services

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/runtime"
)

func TestDNSLogReaderAcrossCopyTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	write := func(s string) {
		t.Helper()
		if _, err := writer.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}
	var reader runtime.DNSFileTail
	defer reader.Close()
	read := func() []string {
		t.Helper()
		lines, err := reader.Read(path)
		if err != nil {
			t.Fatal(err)
		}
		return lines
	}
	write("history\n")
	if lines := read(); len(lines) != 0 {
		t.Fatalf("replayed history: %q", lines)
	}
	write("one\np")
	if lines := read(); !reflect.DeepEqual(lines, []string{"one"}) {
		t.Fatal(lines)
	}
	write("art\n")
	// Fail after the archive is written. The live cursor and pending fragment
	// must still be usable on the successful retry.
	failTruncate := func(f *os.File, archived os.FileInfo, start int64) error {
		ro, err := os.Open(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		defer ro.Close()
		return reader.CopyTruncate(ro, archived, start)
	}
	if err := rotateDNSLog(path, 16, nil, failTruncate); err == nil {
		t.Fatal("read-only truncate succeeded")
	}
	if err := rotateDNSLog(path, 16, nil, reader.CopyTruncate); err != nil {
		t.Fatal(err)
	}
	write("new-one\nnew-two\n")
	if err := rotateDNSLog(path, 16, nil, reader.CopyTruncate); err != nil {
		t.Fatal(err)
	}
	write("new-one\nnew-two\n")
	var got []string
	for range 6 {
		got = append(got, read()...)
	}
	want := []string{"part", "new-one", "new-two", "new-one", "new-two"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDNSLogReaderKeepsCompleteLinesInRetainedArchives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("")
	var r runtime.DNSFileTail
	defer r.Close()
	if _, err := r.Read(path); err != nil {
		t.Fatal(err)
	}
	// Four rotations without polling. The retained suffix begins mid-line.
	for _, s := range []string{"first\npa", "rt\naaaa\n", "bbbbbbb\n", "ccccccc\n"} {
		write(s)
		if err := rotateDNSLog(path, 8, nil, r.CopyTruncate); err != nil {
			t.Fatal(err)
		}
	}
	write("ddddddd\n")
	var got []string
	for range 8 {
		lines, err := r.Read(path)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, lines...)
	}
	if want := []string{"aaaa", "bbbbbbb", "ccccccc", "ddddddd"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

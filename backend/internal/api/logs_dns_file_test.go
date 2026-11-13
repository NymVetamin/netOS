package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDNSFilePagesSnapshotAndArchives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	want := []string{}
	for file := 0; file < 4; file++ {
		var text strings.Builder
		for i := 0; i < 750; i++ {
			fmt.Fprintf(&text, "file%d row%d\n", file, i)
		}
		name := path
		if file > 0 {
			name += fmt.Sprint(".", file)
		}
		if err := os.WriteFile(name, []byte(text.String()), 0600); err != nil {
			t.Fatal(err)
		}
		for i := 749; i >= 0; i-- {
			want = append(want, fmt.Sprintf("file%d row%d", file, i))
		}
	}
	var pos *dnsFilePosition
	got := []string{}
	seen := map[string]bool{}
	for page := 0; page < 40; page++ {
		rows, next, err := readDNSFileBatch(context.Background(), path, pos)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 501 {
			t.Fatal("unbounded rows")
		}
		if page == 0 {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString("new record\n")
			f.Close()
			again, _, err := readDNSFileBatch(context.Background(), path, &next)
			if err != nil || !reflect.DeepEqual(rows, again) {
				t.Fatal("snapshot changed after append", err)
			}
		}
		// Emulate a merge that consumes only part of the lookahead batch.
		for _, row := range rows[:min(len(rows), 100)] {
			if seen[row.ID] {
				t.Fatal("duplicate", row.ID)
			}
			seen[row.ID] = true
			got = append(got, row.Text)
			next.Next = row.Next
		}
		pos = &next
		if len(rows) == 0 && pos.Next.File == 4 {
			break
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("lost/reordered rows", len(got), len(want))
	}
}

func TestDNSFileRotationAndIncompleteLine(t *testing.T) {
	for _, mode := range []string{"rename", "copytruncate"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dns.log")
			original := []byte("first\nsecond\npartial")
			os.WriteFile(path, original, 0600)
			rows, pos, err := readDNSFileBatch(context.Background(), path, nil)
			if err != nil || len(rows) != 2 || rows[0].Text != "second" {
				t.Fatal(rows, err)
			}
			if mode == "rename" {
				if err = os.Rename(path, path+".1"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.WriteFile(path+".1", original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			os.WriteFile(path, []byte(strings.Repeat("new\n", 100)), 0600)
			if _, _, err = readDNSFileBatch(context.Background(), path, &pos); !errors.Is(err, errDNSFileChanged) {
				t.Fatal("rotation accepted", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "dns.log")
	os.WriteFile(path, []byte(strings.Repeat("x", dnsPageBytes+1)), 0600)
	if _, _, err := readDNSFileBatch(context.Background(), path, nil); err == nil {
		t.Fatal("oversized incomplete line ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := readDNSFileBatch(ctx, path, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func BenchmarkDNSFileBatch(b *testing.B) {
	for _, n := range []int{30, 3000, 300000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "dns.log")
			if err := os.WriteFile(path, []byte(strings.Repeat("2026/11/13 13:00:00 dnsmasq[1]: query[A] fixture.invalid from 192.0.2.1\n", n)), 0600); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rows, _, err := readDNSFileBatch(context.Background(), path, nil)
				if err != nil || len(rows) != min(n, 501) {
					b.Fatal(len(rows), err)
				}
			}
		})
	}
}

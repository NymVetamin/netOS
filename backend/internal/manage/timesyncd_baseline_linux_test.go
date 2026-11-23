package manage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTimesyncdSymlinkBaselineRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		exists bool
	}{
		{"relative", "local.conf", true},
		{"absolute", "/dev/null", true},
		{"dangling", "../missing-\xff.conf", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			path := m.sys("/etc/systemd/timesyncd.conf.d/90-netos.conf")
			dir := filepath.Dir(path)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, tc.target)
			if tc.exists && !filepath.IsAbs(tc.target) {
				if err := os.WriteFile(target, []byte("before"), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(tc.target, path); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := captureSystemBaseline(ctx, &baselineRunner{}, m.Root); err != nil {
				t.Fatal(err)
			}
			b, err := m.readSystemBaseline()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if tc.exists && !filepath.IsAbs(tc.target) {
				if err := os.WriteFile(target, []byte("after"), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "keep"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.restoreBaselineHostSettings(ctx, b); err == nil {
				t.Fatal("replaced a directory")
			}
			if err := os.Remove(filepath.Join(path, "keep")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("managed"), 0o644); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if err := m.restoreBaselineHostSettings(ctx, b); err != nil {
					t.Fatal(err)
				}
				if got, err := os.Readlink(path); err != nil || got != tc.target {
					t.Fatalf("readlink = %q, %v; want %q", got, err, tc.target)
				}
			}
			if !tc.exists {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("expected dangling link: %v", err)
				}
			} else if !filepath.IsAbs(tc.target) {
				if data, err := os.ReadFile(path); err != nil || string(data) != "after" {
					t.Fatalf("target changed: %q, %v", data, err)
				}
			}
		})
	}
}

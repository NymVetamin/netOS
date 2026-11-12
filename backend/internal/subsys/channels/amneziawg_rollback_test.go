package channels

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Native AWG retains an omitted I1 across syncconf, unlike channelRunner's
// complete file replacement. Only deleting the link clears the signature.
type stickyAWGRunner struct {
	*awgRunner
	signature          string
	failRollbackDelete bool
}

func (r *stickyAWGRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	deleting := name == "ip" && strings.Join(args, " ") == "link delete wg-ch1"
	if deleting && r.failed && r.failRollbackDelete {
		r.failRollbackDelete = false
		return "", errors.New("injected rollback delete failure")
	}
	out, err := r.awgRunner.Run(ctx, name, args...)
	if err != nil {
		return out, err
	}
	if deleting {
		r.signature = ""
	}
	if name == "awg" && len(args) > 0 && args[0] == "syncconf" {
		data, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(line, "I1 = "); ok {
				r.signature = value
			}
		}
	}
	return out, nil
}

func TestAmneziaWGRollbackRestoresSignatureAndRetry(t *testing.T) {
	for _, tc := range []struct {
		name, old, next string
		failDelete      bool
	}{
		{"add", "", "<b 0xc0ffee>", false},
		{"remove", "<b 0xc0ffee>", "", false},
		{"change", "<b 0xc0ffee>", "<r 8>", false},
		{"unchanged", "<r 8>", "<r 8>", false},
		{"retry-delete", "", "<b 0xc0ffee>", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, inner := newAWGSubsystem(t)
			r := &stickyAWGRunner{awgRunner: inner}
			s.Runner = r
			old, next := awgChannelConfig(), awgChannelConfig()
			for i, cfg := range []*config.Config{old, next} {
				params := cfg.Channels[len(cfg.Channels)-1].Config["amneziawg"].(map[string]any)
				delete(params, "i1")
				if value := []string{tc.old, tc.next}[i]; value != "" {
					params["i1"] = value
				}
			}
			ctx := context.Background()
			if err := s.Apply(ctx, old); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.StateDir, "wg-ch1.conf")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			r.failOnce, r.failed = "ip link set dev wg-ch1 mtu", false
			r.failRollbackDelete = tc.failDelete
			err = s.Apply(ctx, next)
			if err == nil {
				t.Fatal("expected MTU failure")
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tc.failDelete {
				if !strings.Contains(err.Error(), "injected rollback delete failure") {
					t.Fatalf("rollback error lost: %v", err)
				}
				if string(before) == string(after) {
					t.Fatal("failed rollback hid changed runtime from retry")
				}
			} else {
				if r.signature != tc.old {
					t.Fatalf("rollback signature: got %q, want %q", r.signature, tc.old)
				}
				if string(before) != string(after) {
					t.Fatal("rollback did not restore original file")
				}
			}
			if err := s.Apply(ctx, old); err != nil {
				t.Fatal(err)
			}
			if r.signature != tc.old {
				t.Fatalf("retry old signature: got %q, want %q", r.signature, tc.old)
			}
			if tc.old == tc.next && r.count("ip link delete wg-ch1") != 0 {
				t.Fatal("unchanged obfuscation interrupted tunnel")
			}
			if err := s.Apply(ctx, next); err != nil {
				t.Fatal(err)
			}
			if r.signature != tc.next {
				t.Fatalf("retry new signature: got %q, want %q", r.signature, tc.next)
			}
			if err := s.Health(ctx, next); err != nil {
				t.Fatal(err)
			}
		})
	}
}

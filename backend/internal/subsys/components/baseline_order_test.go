package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type baselineOrderRunner struct{ purged bool }

func (r *baselineOrderRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	switch name {
	case "systemctl":
		if args[0] == "is-active" {
			return "inactive", nil
		}
		return "disabled", nil
	case "dpkg-query":
		if strings.Contains(cmd, "${Version}") {
			return "pppoe\t3.15-2\tii \n", nil
		}
		if p := args[len(args)-1]; p == "xl2tpd" || p == "pppoe" {
			return "install ok installed", nil
		}
		return "", errors.New("not installed")
	case "apt-mark":
		return "", nil
	case "apt-get":
		if strings.Contains(cmd, "--download-only") {
			return "", errors.New("original package unavailable")
		}
		r.purged = true
		return "", nil
	}
	return "", nil
}

func (r *baselineOrderRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestApplyCapturesLaterDependentBeforeFirstPurge(t *testing.T) {
	r := &baselineOrderRunner{}
	s := New(r, testLogger{})
	s.Packages.OwnershipDir = t.TempDir()
	if err := system.WritePackageNames(filepath.Join(s.Packages.OwnershipDir, "initial.txt"), map[string]bool{"pppoe": true}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Packages.OwnershipDir, "restore-components"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	err := s.Apply(context.Background(), &config.Config{})
	if err == nil || !strings.Contains(err.Error(), "original package unavailable") {
		t.Fatalf("error=%v", err)
	}
	if r.purged {
		t.Fatal("L2TP purge ran before the original dependent PPPoE package was saved")
	}
}

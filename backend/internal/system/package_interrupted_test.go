package system

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// dpkgPolicyRunner records whether dpkg ran under the daemon policy.
type dpkgPolicyRunner struct {
	packageRunner
	dpkgErr       error
	dpkgSawPolicy bool
}

func (r *dpkgPolicyRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "dpkg" {
		r.commands = append(r.commands, name+" "+strings.Join(args, " "))
		_, err := os.Stat(r.policyPath)
		r.dpkgSawPolicy = err == nil
		return "", r.dpkgErr
	}
	return r.packageRunner.Run(ctx, name, args...)
}

func (r *dpkgPolicyRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestPackageOperationsFinishInterruptedDpkgFirst(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		path := withTestPolicyPath(t)
		r := &dpkgPolicyRunner{packageRunner: packageRunner{installed: map[string]bool{}, policyPath: path}}
		p := NewPackages(r)
		run := func() error {
			if upgrade {
				return p.Upgrade(context.Background(), []string{"pkg=2"})
			}
			_, err := p.Ensure(context.Background(), "pkg")
			return err
		}
		for attempt := 0; attempt < 2; attempt++ { // a retry repeats the same order
			r.commands = nil
			if err := run(); err != nil {
				t.Fatal(err)
			}
			configure, apt := -1, -1
			for i, c := range r.commands {
				if c == "dpkg --configure -a" {
					configure = i
				} else if strings.HasPrefix(c, "apt-get ") && strings.Contains(c, " install ") {
					apt = i
				}
			}
			if configure < 0 || apt < configure || !r.dpkgSawPolicy {
				t.Fatalf("upgrade=%v commands=%v policy=%v", upgrade, r.commands, r.dpkgSawPolicy)
			}
		}
		r.dpkgErr = errors.New("dpkg: locked")
		r.commands = nil
		if err := run(); err == nil || !strings.Contains(err.Error(), "прерванной установки") {
			t.Fatalf("upgrade=%v dpkg failure: %v", upgrade, err)
		}
		for _, c := range r.commands {
			if strings.HasPrefix(c, "apt-get ") && strings.Contains(c, " install ") {
				t.Fatalf("apt ran after dpkg failure: %v", r.commands)
			}
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("policy left after dpkg failure: %v", err)
		}
	}
}

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ownershipRunner struct{ after, fail, inventoryFails bool }

func (r *ownershipRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "dpkg" && strings.Join(args, " ") == "--configure -a" {
		return "", nil
	}
	if name == "apt-get" {
		r.after = true
		if r.fail {
			return "", errors.New("partial apt failure")
		}
		return "", nil
	}
	if name == "dpkg-query" && strings.Contains(strings.Join(args, " "), "binary:Package") {
		if r.after && r.inventoryFails {
			return "", errors.New("dpkg-query failed")
		}
		out := "base:amd64\tii \nforeign\tii \n"
		if r.after {
			out += "unbound\tii \nlibnew:amd64\tii \noriginal-reinstalled\tii \n"
		}
		return out, nil
	}
	return "", errors.New("not installed")
}
func (r *ownershipRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestEnsureRecordsDependenciesEvenAfterPartialFailure(t *testing.T) {
	withTestPolicyPath(t)
	for _, fail := range []bool{false, true} {
		dir := t.TempDir()
		if err := WritePackageNames(filepath.Join(dir, "initial.txt"), map[string]bool{"base:amd64": true, "original-reinstalled": true}); err != nil {
			t.Fatal(err)
		}
		r := &ownershipRunner{fail: fail}
		p := &Packages{R: r, OwnershipDir: dir}
		_, err := p.Ensure(context.Background(), "unbound")
		if (err != nil) != fail {
			t.Fatalf("err=%v", err)
		}
		owned, err := ReadPackageNames(filepath.Join(dir, "owned.txt"))
		if err != nil || len(owned) != 2 || !owned["unbound"] || !owned["libnew:amd64"] {
			t.Fatalf("owned=%v err=%v", owned, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "pending")); !os.IsNotExist(err) {
			t.Fatal("pending marker retained")
		}
	}
}

func TestPendingPackageTransactionBlocksAnotherInstall(t *testing.T) {
	withTestPolicyPath(t)
	dir := t.TempDir()
	_ = WritePackageNames(filepath.Join(dir, "initial.txt"), map[string]bool{})
	_ = os.WriteFile(filepath.Join(dir, "pending"), nil, 0600)
	r := &ownershipRunner{}
	p := &Packages{R: r, OwnershipDir: dir}
	if _, err := p.Ensure(context.Background(), "unbound"); err == nil || r.after {
		t.Fatal("unresolved transaction ignored")
	}
}

// Пакеты встали, а учёт не записался: ошибка должна называть только учёт,
// без «<nil>;» от несуществующей ошибки установки.
func TestPackageCaptureFailureAfterSuccessfulInstall(t *testing.T) {
	withTestPolicyPath(t)
	for _, run := range []func(*Packages) error{
		func(p *Packages) error { _, err := p.Ensure(context.Background(), "unbound"); return err },
		func(p *Packages) error { return p.Upgrade(context.Background(), []string{"unbound=1"}) },
	} {
		dir := t.TempDir()
		if err := WritePackageNames(filepath.Join(dir, "initial.txt"), map[string]bool{"base:amd64": true}); err != nil {
			t.Fatal(err)
		}
		err := run(&Packages{R: &ownershipRunner{inventoryFails: true}, OwnershipDir: dir})
		if err == nil || strings.Contains(err.Error(), "<nil>") || !strings.Contains(err.Error(), "dpkg-query failed") {
			t.Fatalf("err=%v", err)
		}
	}
}

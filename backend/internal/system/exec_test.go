package system

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExecHelperProcess(t *testing.T) {
	if os.Getenv("NETOS_EXEC_HELPER") != "1" {
		return
	}
	mode := os.Getenv("NETOS_EXEC_MODE")
	switch mode {
	case "stdin":
		data, _ := io.ReadAll(os.Stdin)
		_, _ = os.Stdout.Write(data)
	case "fail-stderr":
		_, _ = os.Stderr.WriteString("deliberate stderr")
		os.Exit(7)
	case "fail-stdout":
		_, _ = os.Stdout.WriteString("deliberate stdout")
		os.Exit(8)
	case "sleep":
		time.Sleep(5 * time.Second)
	default:
		_, _ = os.Stdout.WriteString("ok")
	}
}

func helperCommand(t *testing.T, mode string) (string, []string) {
	t.Helper()
	t.Setenv("NETOS_EXEC_HELPER", "1")
	t.Setenv("NETOS_EXEC_MODE", mode)
	return os.Args[0], []string{"-test.run=^TestExecHelperProcess$"}
}

func TestExecRunInputErrorsTimeoutAndCallback(t *testing.T) {
	name, args := helperCommand(t, "success")
	execRunner := NewExec()
	if execRunner.Timeout != 30*time.Second || execRunner.PackageTimeout != 15*time.Minute {
		t.Fatalf("unexpected defaults: %+v", execRunner)
	}
	var calledName string
	var calledArgs []string
	execRunner.OnCommand = func(name string, args []string) {
		calledName = name
		calledArgs = append([]string(nil), args...)
	}
	out, err := execRunner.Run(context.Background(), name, args...)
	if err != nil || !strings.HasPrefix(out, "ok") || calledName != name || strings.Join(calledArgs, " ") != strings.Join(args, " ") {
		t.Fatalf("Run output=%q err=%v callback=%q %v", out, err, calledName, calledArgs)
	}
	name, args = helperCommand(t, "stdin")
	out, err = execRunner.RunInput(context.Background(), "input payload", name, args...)
	if err != nil || !strings.HasPrefix(out, "input payload") {
		t.Fatalf("RunInput output=%q err=%v", out, err)
	}

	for _, tc := range []struct {
		mode string
		want string
	}{
		{"fail-stderr", "deliberate stderr"},
		{"fail-stdout", "deliberate stdout"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			name, args := helperCommand(t, tc.mode)
			_, err := NewExec().Run(context.Background(), name, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), name) {
				t.Fatalf("error=%v", err)
			}
		})
	}

	t.Run("timeout", func(t *testing.T) {
		name, args := helperCommand(t, "sleep")
		runner := NewExec()
		runner.Timeout = 50 * time.Millisecond
		started := time.Now()
		_, err := runner.Run(context.Background(), name, args...)
		if err == nil || time.Since(started) > 2*time.Second {
			t.Fatalf("timeout err=%v elapsed=%v", err, time.Since(started))
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		name, args := helperCommand(t, "sleep")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := NewExec().Run(ctx, name, args...)
		if err == nil {
			t.Fatal("cancelled command succeeded")
		}
	})

	t.Run("missing executable", func(t *testing.T) {
		_, err := NewExec().Run(context.Background(), "netos-command-that-does-not-exist")
		if err == nil {
			t.Fatal("missing executable succeeded")
		}
	})
}

func TestWriteFileAtomicAndFileChanged(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator) + "nested" + string(os.PathSeparator) + "config"
	if !FileChanged(path, []byte("first")) {
		t.Fatal("missing file reported unchanged")
	}
	if err := WriteFileAtomic(path, []byte("first"), 0o640); err != nil {
		t.Fatal(err)
	}
	if FileChanged(path, []byte("first")) || !FileChanged(path, []byte("second")) {
		t.Fatal("FileChanged comparison is incorrect")
	}
	if err := WriteFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "second" {
		t.Fatalf("content=%q err=%v", data, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
		}
	}
}

func TestWriteFileAtomicIfChangedPreservesMatchingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	changed, err := WriteFileAtomicIfChanged(path, []byte("same"), 0o600)
	if err != nil || !changed {
		t.Fatalf("initial write changed=%v err=%v", changed, err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	changed, err = WriteFileAtomicIfChanged(path, []byte("same"), 0o600)
	if err != nil || changed {
		t.Fatalf("matching write changed=%v err=%v", changed, err)
	}
	after, err := os.Stat(path)
	if err != nil || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("matching write replaced file: before=%v after=%v err=%v", before.ModTime(), after.ModTime(), err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		changed, err = WriteFileAtomicIfChanged(path, []byte("same"), 0o600)
		if err != nil || !changed {
			t.Fatalf("mode drift changed=%v err=%v", changed, err)
		}
	}
}

func TestWriteFileAtomicReportsInvalidParent(t *testing.T) {
	parent := t.TempDir() + string(os.PathSeparator) + "file"
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(parent+string(os.PathSeparator)+"child", []byte("x"), 0o600); err == nil {
		t.Fatal("write below regular file succeeded")
	}
}

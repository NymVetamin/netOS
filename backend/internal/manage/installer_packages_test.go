package manage

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallerPreservesAutoMarksWithLargePackageList(t *testing.T) {
	bash := "bash"
	if runtime.GOOS == "windows" {
		bash = "C:/Program Files/Git/bin/bash.exe"
	}
	if _, err := exec.LookPath(bash); err != nil {
		t.Skip("bash unavailable")
	}
	source := installerSource(t)
	start := strings.Index(source, `AUTO_PACKAGES=""`)
	end := strings.Index(source[start:], "# Keep package ownership") + start
	script := `set -euo pipefail
PACKAGES="ethtool missing"
dpkg-query() { printf 'ii '; }
apt-mark() {
    printf 'ethtool\n'
    for ((i=0; i<10000; i++)); do printf 'dependency-%05d\n' "$i"; done
}
` + source[start:end] + `
test "$AUTO_PACKAGES" = " ethtool" || { echo "lost automatic packages: [$AUTO_PACKAGES]"; exit 1; }
`
	path := filepath.Join(t.TempDir(), "auto.sh")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bash, filepath.ToSlash(path)).CombinedOutput(); err != nil {
		t.Fatalf("auto package capture: %v: %s", err, out)
	}
}

func TestInstallerTracksAptPackagesAcrossRetries(t *testing.T) {
	bash := "bash"
	if runtime.GOOS == "windows" {
		bash = "C:/Program Files/Git/bin/bash.exe"
	}
	if _, err := exec.LookPath(bash); err != nil {
		t.Skip("bash unavailable")
	}
	source := installerSource(t)
	start := strings.Index(source, "PACKAGE_STATE=/var/lib/netos-package-state")
	end := strings.Index(source[start:], "# --- бинарник") + start
	block := strings.ReplaceAll(source[start:end], "PACKAGE_STATE=/var/lib/netos-package-state", `PACKAGE_STATE="$QA_DIR/ledger"`)
	for _, fail := range []bool{false, true} {
		dir := t.TempDir()
		script := `set -eu
PACKAGES="iptables"
AUTO_PACKAGES=""
die() { echo "$*" >&2; exit 1; }
ok() { :; }
warn() { :; }
dpkg-query() { cat "$QA_DIR/live"; }
apt-get() {
    case "$1" in install)
        printf 'base\tii \niptables\tii \nlibnew:amd64\tii \n' > "$QA_DIR/live"
        [ "$QA_FAIL" = 0 ] ;;
    esac
}
` + block
		if runtime.GOOS == "windows" {
			// Git Bash cannot apply POSIX modes to Go's restricted Windows temp
			// directory. Test the package transaction with filesystem ACLs intact.
			script = strings.Replace(script, "set -eu\n", "set -eu\ninstall() { mkdir -p \"$4\"; }\nchmod() { :; }\n", 1)
		}
		path := filepath.Join(dir, "packages.sh")
		if err := os.WriteFile(path, []byte(script), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "live"), []byte("base\tii \n"), 0600); err != nil {
			t.Fatal(err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			cmd := exec.Command(bash, filepath.ToSlash(path))
			failValue := "0"
			if fail {
				failValue = "1"
			}
			cmd.Env = append(os.Environ(), "QA_DIR="+filepath.ToSlash(dir), "QA_FAIL="+failValue)
			out, err := cmd.CombinedOutput()
			if (err != nil) != fail {
				t.Fatalf("err=%v out=%s", err, out)
			}
			owned, err := os.ReadFile(filepath.Join(dir, "ledger", "owned.txt"))
			if err != nil || string(owned) != "iptables\nlibnew:amd64\n" {
				t.Fatalf("owned=%q err=%v", owned, err)
			}
			initial, err := os.ReadFile(filepath.Join(dir, "ledger", "initial.txt"))
			if err != nil || string(initial) != "base\n" {
				t.Fatalf("initial=%q err=%v", initial, err)
			}
		}
	}
}

package manage

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBashCompletionInCurrentShellWithoutFramework(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if runtime.GOOS == "windows" {
		// The Windows system bash.exe is a WSL launcher, not a Bash runtime.
		bash = filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		_, err = os.Stat(bash)
	}
	if err != nil {
		t.Skip("Bash runtime unavailable")
	}
	path := filepath.Join(t.TempDir(), "netos-completion")
	if err := os.WriteFile(path, []byte(bashCompletion()), 0644); err != nil {
		t.Fatal(err)
	}
	// Same command printed by the installer; no new login, framework or
	// root privileges required. Exercise command and new option completion.
	script := `set -e
source "$1"
complete -p netos | grep -q '_netos'
COMP_WORDS=(netos un); COMP_CWORD=1; _netos
[[ "${COMPREPLY[*]}" == uninstall ]]
COMP_WORDS=(netos uninstall --b); COMP_CWORD=2; _netos
[[ "${COMPREPLY[*]}" == --backup ]]
COMP_WORDS=(netos uninstall --no); COMP_CWORD=2; _netos
[[ "${COMPREPLY[*]}" == --no-backup ]]
COMP_WORDS=(netos ''); COMP_CWORD=1; _netos
[[ " ${COMPREPLY[*]} " == *' status '* && " ${COMPREPLY[*]} " == *' uninstall '* ]]
`
	cmd := exec.Command(bash, "--noprofile", "--norc", "-c", script, "bash", filepath.ToSlash(path))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("completion failed: %v\n%s", err, output)
	}
}

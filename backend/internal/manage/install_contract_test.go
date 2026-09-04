package manage

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func installerSource(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "install.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInstallerSyntaxAndTransactionalOrdering(t *testing.T) {
	source := installerSource(t)
	for _, required := range []string{
		`PORT=$((10#$PORT))`, `Environment=NETOS_INITIAL_PORT=$PORT`,
		`-capture-system-baseline`, `BASELINE_DIR/.capture-required`,
		`PANEL_PORT=$("$BIN_PATH" -panel-port`, `trap rollback_and_cleanup EXIT`,
		`snapshot_path /etc/apt/apt.conf.d/99netos aptconf`,
		`chmod 0644 /etc/apt/apt.conf.d/99netos`,
		`chmod 0644 /etc/bash_completion.d/netos`,
		`chmod 0644 /etc/systemd/system/netosd.service`,
		`apt-mark showauto`, `apt-mark auto $AUTO_PACKAGES`,
		`snapshot_path "$STATE_DIR" state-dir`, `restore_path "$STATE_DIR" state-dir`,
		`uninstall --keep-data --yes`, `rm -f /run/netosd.ready`,
		`wait_netosd_ready 360`, `ROLLBACK_ARMED=1`, `ROLLBACK_ARMED=0`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("installer contract is missing %q", required)
		}
	}
	order := func(needle string) int {
		index := strings.Index(source, needle)
		if index < 0 {
			t.Fatalf("installer is missing %q", needle)
		}
		return index
	}
	if !(order(`snapshot_path /etc/apt/apt.conf.d/99netos aptconf`) < order(`cat > /etc/apt/apt.conf.d/99netos`) &&
		order(`snapshot_path "$STATE_DIR" state-dir`) < order(`install -d -m 0700 "$STATE_DIR"`) &&
		order(`ROLLBACK_ARMED=1`) < order(`cat > /etc/apt/apt.conf.d/99netos`) &&
		order(`ROLLBACK_ARMED=1`) < order(`install -m 0755 "$CANDIDATE" "$BIN_PATH.new"`) &&
		order(`-capture-system-baseline`) < order(`if ! systemctl restart netosd; then`) &&
		strings.LastIndex(source, `rm -f /run/netosd.ready`) < order(`if ! systemctl restart netosd; then`) &&
		strings.LastIndex(source, `wait_netosd_ready 360`) > order(`if ! systemctl restart netosd; then`) &&
		strings.LastIndex(source, `ROLLBACK_ARMED=0`) > order(`if [ "$START_OK" = "0" ]`)) {
		t.Fatal("installer transaction steps are in an unsafe order")
	}
	if runtime.GOOS != "windows" {
		bash, err := exec.LookPath("bash")
		if err != nil {
			t.Skip("bash is unavailable")
		}
		cmd := exec.Command(bash, "-n", filepath.Join("..", "..", "..", "install.sh"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bash -n failed: %v\n%s", err, output)
		}
	}
}

func TestDevPushWaitsForAppliedStateAndRollsBack(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scripts", "dev-push.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		`snapshot_path "$BIN_PATH" binary`, `rm -f "$READY_PATH"`, `wait_ready`,
		`NETOS_EXPECTED_SHA=$CANDIDATE_SHA`, `verify_binary`, `NRestarts --value`,
		`netosd завершился до готовности`, `systemctl reset-failed netosd`, `verify_plan`,
		`restore_path "$BIN_PATH" binary`, `systemctl --failed --no-legend --plain`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("dev-push contract is missing %q", required)
		}
	}
	if strings.Count(source, `&& verify_binary`) != 2 {
		t.Fatal("dev-push must verify the candidate both before restart and after readiness")
	}
	order := func(needle string) int {
		index := strings.Index(source, needle)
		if index < 0 {
			t.Fatalf("dev-push is missing %q", needle)
		}
		return index
	}
	if !(order(`snapshot_path "$BIN_PATH" binary`) < order(`mv -f "$BIN_PATH.new" "$BIN_PATH"`) &&
		order(`rm -f "$READY_PATH"`) < order(`systemctl restart netosd`) &&
		order(`systemctl restart netosd`) < strings.Index(source[order(`systemctl restart netosd`):], `wait_ready`)+order(`systemctl restart netosd`) &&
		strings.LastIndex(source, `restore_path "$BIN_PATH" binary`) > order(`НОВАЯ ВЕРСИЯ НЕ ПОДТВЕРДИЛА ГОТОВНОСТЬ`)) {
		t.Fatal("dev-push deploy transaction is in an unsafe order")
	}
	workflow, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "shellcheck --severity=warning install.sh scripts/dev-push.sh") {
		t.Fatal("CI does not shellcheck dev-push.sh")
	}
}

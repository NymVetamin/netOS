package manage

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		`PORT=$((10#$PORT))`,
		`Environment=NETOS_INITIAL_PORT=$PORT`,
		`-capture-system-baseline`,
		`BASELINE_DIR/.capture-required`,
		`PANEL_PORT=$("$BIN_PATH" -panel-port`,
		`trap rollback_and_cleanup EXIT`,
		`snapshot_path /etc/apt/apt.conf.d/99netos aptconf`,
		`chmod 0644 /etc/apt/apt.conf.d/99netos`,
		`chmod 0644 /etc/bash_completion.d/netos`,
		`chmod 0644 /etc/systemd/system/netosd.service`,
		`apt-mark showauto`,
		`apt-mark auto $AUTO_PACKAGES`,
		`snapshot_path "$STATE_DIR" state-dir`,
		`restore_path "$STATE_DIR" state-dir`,
		`uninstall --keep-data --yes`,
		`rm -f /run/netosd.ready`,
		`wait_netosd_ready 360`,
		`ROLLBACK_ARMED=1`,
		`ROLLBACK_ARMED=0`,
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
		`snapshot_path "$BIN_PATH" binary`,
		`rm -f "$READY_PATH"`,
		`wait_ready`,
		`NETOS_EXPECTED_SHA=$CANDIDATE_SHA`,
		`verify_binary`,
		`NRestarts --value`,
		`netosd завершился до готовности`,
		`systemctl reset-failed netosd`,
		`verify_plan`,
		`restore_path "$BIN_PATH" binary`,
		`systemctl --failed --no-legend --plain`,
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
	if !strings.Contains(string(workflow), "shellcheck --severity=warning install.sh scripts/dev-deploy.sh scripts/dev-push.sh") {
		t.Fatal("CI does not shellcheck dev-push.sh")
	}
}

func TestDevDeployBuildsFromCleanTreeBeforeTransactionalActivation(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scripts", "dev-deploy.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		`set -euo pipefail`,
		`*) echo "неизвестный параметр: $arg"`,
		`/opt/netos.upload`,
		`set -o pipefail && go mod tidy`,
		`CGO_ENABLED=0 go build -trimpath`,
		`-o /opt/netos/netosd.candidate`,
		`NETOS_BINARY_FILE="$CANDIDATE"`,
		`"$REPO/scripts/dev-push.sh"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("dev-deploy contract is missing %q", required)
		}
	}
	order := func(needle string) int {
		index := strings.Index(source, needle)
		if index < 0 {
			t.Fatalf("dev-deploy is missing %q", needle)
		}
		return index
	}
	if !(order(`/opt/netos.upload`) < order(`go mod tidy`) &&
		order(`go mod tidy`) < order(`cat /opt/netos/backend/go.mod`) &&
		order(`go mod tidy`) < order(`go build -trimpath`) &&
		order(`go build -trimpath`) < order(`"$REPO/scripts/dev-push.sh"`)) {
		t.Fatal("dev-deploy validation/activation steps are in an unsafe order")
	}
}

func TestQABeforeAfterScriptsCoverStableHostState(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	capture := read("qa-capture-state.sh")
	for _, required := range []string{
		`render_list=$(netos render --list)`,
		`packages-manual.txt`, `netos-unit-health.txt`, `host-service-state.txt`,
		`ip-address-v6.txt`, `ip-rule-v6.txt`, `ip-route-v6.txt`, `ipset-save.txt`,
		`listeners-stable.txt`, `tc-config.txt`, `sysctl-managed.txt`,
		`sysctl-per-interface.txt`, `managed-system-files.txt`, `netos-journal.txt`,
	} {
		if !strings.Contains(capture, required) {
			t.Fatalf("QA state capture is missing %q", required)
		}
	}
	if strings.Contains(capture, "for artifact in iptables") {
		t.Fatal("QA capture hardcodes render artifacts instead of using the shared catalog")
	}

	compare := read("qa-compare-state.sh")
	for _, required := range []string{
		`verify_manifest "$before"`, `verify_manifest "$after"`,
		`EXACT_HOST_STATE`, `compare_exact "$name"`, `BACKUP_VS_LIVE`,
		`Живая система соответствует конфигурации: применять нечего.`,
		`/run/netosd.ready`, `systemctl --failed --no-legend --plain`,
		`exit 1`, `PASS: exact before/after host state and restored artifacts`,
	} {
		if !strings.Contains(compare, required) {
			t.Fatalf("QA state comparison is missing %q", required)
		}
	}

	remote := read("qa-remote.py")
	if !strings.Contains(remote, "paramiko.RejectPolicy()") || strings.Contains(remote, "paramiko.AutoAddPolicy()") {
		t.Fatal("QA SSH helper does not fail closed on an unknown host key")
	}
}

func TestLiveAPIRunnerAccountsForEveryRoute(t *testing.T) {
	serverPath := filepath.Join("..", "api", "server.go")
	serverData, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	routePattern := regexp.MustCompile(`(?:mux\.HandleFunc|auth)\("([A-Z]+ /api/[^" ]*)"`)
	matches := routePattern.FindAllStringSubmatch(string(serverData), -1)
	if len(matches) == 0 {
		t.Fatal("no API routes discovered")
	}

	// Empty marker means that success is intentionally destructive and belongs
	// to the monitored Apply/restore/backup lifecycle rather than the safe API sweep.
	markers := map[string]string{
		"POST /api/login":                       `Invoke-NetOSRequest POST "/api/login"`,
		"GET /api/ping":                         `Invoke-NetOSRequest GET "/api/ping"`,
		"POST /api/logout":                      `Invoke-NetOSRequest POST "/api/logout"`,
		"GET /api/session":                      `Invoke-NetOSRequest GET "/api/session"`,
		"POST /api/password":                    `Invoke-NetOSRequest POST "/api/password"`,
		"POST /api/wireguard/keypair":           `Invoke-NetOSRequest POST "/api/wireguard/keypair"`,
		"POST /api/xray/keypair":                `Invoke-NetOSRequest POST "/api/xray/keypair"`,
		"GET /api/vpn-servers/{id}/certificate": `Invoke-NetOSRequest GET ("/api/vpn-servers/"`,
		"GET /api/config":                       `Invoke-NetOSRequest GET "/api/config"`,
		"PUT /api/config":                       `Invoke-NetOSRequest PUT "/api/config"`,
		"POST /api/config/validate":             `Invoke-NetOSRequest POST "/api/config/validate"`,
		"POST /api/config/plan":                 `Invoke-NetOSRequest POST "/api/config/plan"`,
		"POST /api/config/apply":                "",
		"POST /api/config/confirm":              `Invoke-NetOSRequest POST "/api/config/confirm"`,
		"POST /api/config/rollback":             `Invoke-NetOSRequest POST "/api/config/rollback"`,
		"POST /api/config/discard":              `Invoke-NetOSRequest POST "/api/config/discard"`,
		"GET /api/revisions":                    `Invoke-NetOSRequest GET "/api/revisions?`,
		"GET /api/revisions/{id}":               `Invoke-NetOSRequest GET ("/api/revisions/"`,
		"POST /api/revisions/{id}/restore":      "",
		"GET /api/catalog":                      `"/api/catalog"`,
		"GET /api/status":                       `"/api/status"`,
		"GET /api/ddns/status":                  `"/api/ddns/status"`,
		"GET /api/statistics":                   `"/api/statistics?`,
		"GET /api/maintenance/status":           `"/api/maintenance/status"`,
		"GET /api/backups":                      `Invoke-NetOSRequest GET "/api/backups"`,
		"GET /api/backups/{name}":               `Invoke-NetOSRequest GET ("/api/backups/"`,
		"POST /api/backups":                     "",
		"DELETE /api/backups/{name}":            `Invoke-NetOSRequest DELETE "/api/backups/`,
		"POST /api/maintenance/restore":         `Invoke-NetOSRequest POST "/api/maintenance/restore"`,
		"POST /api/maintenance/update":          `Invoke-NetOSRequest POST "/api/maintenance/update"`,
		"POST /api/maintenance/panel":           `Invoke-NetOSRequest POST "/api/maintenance/panel"`,
		"GET /api/clients":                      `"/api/clients"`,
		"GET /api/interfaces":                   `"/api/interfaces"`,
		"GET /api/leases":                       `"/api/leases"`,
		"GET /api/arp":                          `"/api/arp"`,
		"GET /api/routes":                       `"/api/routes"`,
		"GET /api/audit":                        `"/api/audit?`,
		"GET /api/render":                       `Invoke-NetOSRequest GET "/api/render"`,
		"GET /api/render/{kind}":                `Invoke-NetOSRequest GET ("/api/render/"`,
	}
	runnerData, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", "qa-live-api.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	runner := string(runnerData)
	seen := map[string]bool{}
	for _, match := range matches {
		route := match[1]
		marker, known := markers[route]
		if !known {
			t.Errorf("API route %q has no live QA classification", route)
			continue
		}
		seen[route] = true
		if marker != "" && !strings.Contains(runner, marker) {
			t.Errorf("safe API route %q is missing runner marker %q", route, marker)
		}
	}
	for route := range markers {
		if !seen[route] {
			t.Errorf("live QA classification refers to missing API route %q", route)
		}
	}
}

func TestDestructiveQACycleIsMonitoredAndRecoverable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", "qa-destructive-cycle.sh"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		`[[ -n ${INVOCATION_ID:-} ]]`,
		`/var/backups/netos/qa-assets-*`,
		`QA asset is not root-owned`,
		`binary checksum mismatch`,
		`monitor_loop`,
		`systemctl --failed --no-legend --plain`,
		`wait_ready`,
		`assert_clean`,
		`capture_stage before`,
		`netos reset --yes --no-backup`,
		`netos restore "$backup" --yes`,
		`netos uninstall --yes`,
		`install_candidate`,
		`"$compare" "$work/before" "$work/after" "$backup"`,
		`python3 "$compare_sqlite"`,
		`attempting automatic recovery`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("destructive QA cycle is missing %q", required)
		}
	}
	order := func(needle string) int {
		index := strings.Index(source, needle)
		if index < 0 {
			t.Fatalf("destructive QA cycle is missing %q", needle)
		}
		return index
	}
	mainStart := order(`echo "STAGE preflight"`)
	main := source[mainStart:]
	position := func(needle string) int {
		index := strings.Index(main, needle)
		if index < 0 {
			t.Fatalf("destructive QA main flow is missing %q", needle)
		}
		return index
	}
	if !(position(`capture_stage before`) < position(`netos reset --yes --no-backup`) &&
		position(`netos reset --yes --no-backup`) < position(`echo "STAGE restore after reset"`) &&
		position(`echo "STAGE restore after reset"`) < position(`netos uninstall --yes`) &&
		position(`netos uninstall --yes`) < position(`echo "STAGE clean install from verified local artifact"`) &&
		position(`echo "STAGE clean install from verified local artifact"`) < position(`echo "STAGE restore original backup after clean install"`) &&
		position(`capture_stage after`) < position(`echo "STAGE SQLite comparison"`)) {
		t.Fatal("destructive QA lifecycle stages are in an unsafe order")
	}
}

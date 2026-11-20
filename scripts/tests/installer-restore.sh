#!/bin/bash
set -eu
installer=$(cd "$(dirname "$0")/../.." && pwd)/install.sh
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT

for initial_upgrade in 0 1; do
    PACKAGE_STATE="$root/packages-$initial_upgrade"
    mkdir "$PACKAGE_STATE"
    UPGRADE=$initial_upgrade
    echo first > "$PACKAGE_STATE/before.txt"
    for attempt in 1 2; do
        source <(sed -n '/^if \[ ! -f "\$PACKAGE_STATE\/initial.txt" \]; then$/,/^fi$/p' "$installer")
        [[ $(cat "$PACKAGE_STATE/initial.txt") == first ]]
        if [[ $initial_upgrade == 0 ]]; then
            [[ -f "$PACKAGE_STATE/restore-components" ]]
        else
            [[ ! -e "$PACKAGE_STATE/restore-components" ]]
        fi
        UPGRADE=1
        echo changed > "$PACKAGE_STATE/before.txt"
    done
done

# Run the production rollback functions against a temporary filesystem tree.
# Prefix only the literal OS paths. Variable paths below already live in root.
source <(sed -n -e '/^restore_path() {/,/^}/p' -e '/^rollback_and_cleanup() {/,/^}/p' "$installer" |
    sed -e 's| /etc/| "$root"/etc/|g' -e 's| /usr/| "$root"/usr/|g' -e 's| /run/| "$root"/run/|g')
warn() { echo "$*"; }
systemctl() { :; }
INSTALL_TXN="$root/snapshot"
BIN_PATH="$root/bin/netosd"
CLI_PATH="$root/cli"
STATE_DIR="$root/state"
CONF_DIR="$root/conf"
LOG_DIR="$root/log"
BASELINE_DIR="$root/baseline"
SRC= TMP= ROLLBACK_ARMED=1 UPGRADE=1 PREVIOUS_ENABLED=0 PREVIOUS_ACTIVE=0
mkdir "$INSTALL_TXN"
echo previous > "$INSTALL_TXN/binary"
echo config > "$INSTALL_TXN/conf-dir"
for label in cli unit completion completion-lazy aptconf state-dir log-dir baseline-dir; do
    touch "$INSTALL_TXN/$label.absent"
done
touch "$root/bin" # A file in place of the parent directory makes copying fail.
rollback() (
    set +e
    false
    rollback_and_cleanup
)
if rollback > "$root/first.log" 2>&1; then exit 1; fi
grep -F "$INSTALL_TXN" "$root/first.log" >/dev/null
cmp "$CONF_DIR" "$INSTALL_TXN/conf-dir"
[[ $(cat "$INSTALL_TXN/binary") == previous ]]
rm "$root/bin"
mkdir "$root/bin"
(
    cp -a -- "$INSTALL_TXN" "$root/active-snapshot"
    INSTALL_TXN="$root/active-snapshot"
    PREVIOUS_ACTIVE=1
    systemctl() { [[ $1 != start || $failure != start ]]; }
    wait_netosd_ready() { [[ $failure != ready ]]; }
    for failure in start ready; do
        if rollback > "$root/$failure.log" 2>&1; then exit 1; fi
        [[ -d "$INSTALL_TXN" ]] || { echo "$failure: rollback removed the snapshot" >&2; exit 1; }
        grep -F "$INSTALL_TXN" "$root/$failure.log" >/dev/null
        cmp "$BIN_PATH" "$INSTALL_TXN/binary"
        cmp "$CONF_DIR" "$INSTALL_TXN/conf-dir"
    done
    failure=none
    if rollback > "$root/retry.log" 2>&1; then exit 1; fi
    [[ ! -e "$INSTALL_TXN" ]]
)
if rollback > "$root/second.log" 2>&1; then exit 1; fi
[[ $(cat "$BIN_PATH") == previous && ! -e "$INSTALL_TXN" ]]

(
    ROLLBACK_ARMED=apt
    policy="$root/etc/apt/apt.conf.d/99netos"
    mkdir -p "$(dirname "$policy")" "$STATE_DIR"
    echo committed > "$STATE_DIR/new-revision"
    systemctl() { echo "$*" >> "$root/service-calls"; }
    for previous in absent present; do
        mkdir "$INSTALL_TXN"
        if [[ $previous == absent ]]; then
            touch "$INSTALL_TXN/aptconf.absent"
        else
            echo original > "$INSTALL_TXN/aptconf"
        fi
        echo changed > "$policy"
        if rollback; then exit 1; fi
        [[ ! -e "$INSTALL_TXN" && ! -e "$root/service-calls" ]]
        [[ $(cat "$STATE_DIR/new-revision") == committed ]]
        if [[ $previous == absent ]]; then
            [[ ! -e "$policy" ]]
        else
            [[ $(cat "$policy") == original ]]
        fi
    done
)

# Test rollback after a first install using the actual saved files. Use an
# equivalent path to the executable so readlink -f also works on Git Bash.
UPGRADE=0
CLI_PATH="$root/bin/../bin/netosd"
for scenario in early late success copy-error; do
    mkdir -p "$INSTALL_TXN" "$BASELINE_DIR"
    for label in cli binary unit completion completion-lazy aptconf state-dir conf-dir log-dir; do
        touch "$INSTALL_TXN/$label.absent"
    done
    if [[ "$scenario" == late ]]; then
        mkdir "$INSTALL_TXN/baseline-dir"
        echo previous > "$INSTALL_TXN/baseline-dir/state.json"
    else
        touch "$INSTALL_TXN/baseline-dir.absent"
    fi
    echo captured > "$BASELINE_DIR/state.json"
    cat > "$BIN_PATH" <<'EOF'
#!/bin/bash
[[ "$*" == 'uninstall --keep-data --yes' ]] || exit 2
echo called > "$call_log"
if [[ "$scenario" == late ]]; then rm -rf "$BASELINE_DIR"; fi
[[ "$scenario" == success ]] || exit 42
EOF
    chmod +x "$BIN_PATH"
    call_log="$root/$scenario.called"
    export scenario BASELINE_DIR call_log
    cp() {
        if [[ "$scenario" == copy-error && " $* " == *" $BASELINE_DIR "* ]]; then return 1; fi
        command cp "$@"
    }
    if rollback > "$root/$scenario.log" 2>&1; then exit 1; fi
    [[ -f "$call_log" ]]
    if [[ "$scenario" == copy-error ]]; then
        [[ $(cat "$BASELINE_DIR/state.json") == captured ]]
    fi
    if [[ "$scenario" == success ]]; then
        [[ ! -e "$INSTALL_TXN" && ! -e "$BASELINE_DIR" ]]
    else
        grep -F "$INSTALL_TXN" "$root/$scenario.log" >/dev/null
        if [[ "$scenario" != copy-error ]]; then
            [[ $(cat "$INSTALL_TXN/captured-baseline/state.json") == captured ]]
        fi
        if [[ "$scenario" == late ]]; then
            [[ $(cat "$BASELINE_DIR/state.json") == previous ]]
        fi
    fi
    rm -rf -- "$INSTALL_TXN" "$BASELINE_DIR"
done

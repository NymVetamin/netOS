#!/bin/bash
# Полный destructive QA: reset/restore, uninstall, clean install, restore и
# точное сравнение установленного состояния. Запускать только transient unit:
#   systemd-run --unit=netos-qa-cycle --collect --wait \
#     /var/backups/netos/qa-assets-RUN/qa-destructive-cycle.sh RUN

set -euo pipefail

if [[ $# -ne 1 || ! $1 =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "usage: qa-destructive-cycle.sh RUN_ID" >&2
    exit 2
fi
[[ $(id -u) -eq 0 ]] || { echo "root is required" >&2; exit 1; }
[[ -n ${INVOCATION_ID:-} ]] || {
    echo "refusing interactive execution; use systemd-run so SSH loss cannot stop rollback" >&2
    exit 1
}

run_id=$1
asset_dir=$(dirname "$(readlink -f "$0")")
case "$asset_dir" in
    /var/backups/netos/qa-assets-*) ;;
    *) echo "unsafe asset directory: $asset_dir" >&2; exit 1 ;;
esac

capture="$asset_dir/qa-capture-state.sh"
compare="$asset_dir/qa-compare-state.sh"
compare_sqlite="$asset_dir/qa-compare-sqlite.py"
installer="$asset_dir/install.sh"
binary="$asset_dir/netosd-linux-amd64"
checksum="$binary.sha256"
for path in "$capture" "$compare" "$compare_sqlite" "$installer" "$binary" "$checksum"; do
    [[ -f "$path" && ! -L "$path" ]] || { echo "missing regular QA asset: $path" >&2; exit 1; }
    [[ $(stat -c %u "$path") == 0 ]] || { echo "QA asset is not root-owned: $path" >&2; exit 1; }
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 )) || { echo "QA asset is group/world-writable: $path" >&2; exit 1; }
done
[[ $(uname -m) == x86_64 ]] || { echo "this asset set is amd64-only" >&2; exit 1; }
expected=$(awk 'NR == 1 && $1 ~ /^[0-9a-fA-F]{64}$/ {print tolower($1)}' "$checksum")
[[ -n "$expected" ]] || { echo "invalid binary checksum file" >&2; exit 1; }
actual=$(sha256sum "$binary" | awk '{print $1}')
[[ "$actual" == "$expected" ]] || { echo "binary checksum mismatch" >&2; exit 1; }

work=/var/backups/netos/qa-cycle-$run_id
[[ ! -e "$work" ]] || { echo "refusing to overwrite $work" >&2; exit 1; }
umask 077
install -d -m 0700 "$work"
exec > >(tee -a "$work/cycle.log") 2>&1

monitor_pid=""
backup=""

monitor_loop() {
    while true; do
        printf '\n[%s] ' "$(date -Is)"
        systemctl show netosd -p LoadState -p ActiveState -p SubState -p Result -p NRestarts --value 2>/dev/null \
            | tr '\n' ' ' || true
        printf 'ready='
        if [[ -s /run/netosd.ready ]]; then tr -d '\n' < /run/netosd.ready; else printf absent; fi
        printf ' failed='
        systemctl --failed --no-legend --plain 2>/dev/null | wc -l || true
        ss -H -lnt 2>/dev/null | awk '$4 ~ /:(22|80|8443)$/ {print "listener=" $4}' || true
        sleep 2
    done
}

wait_ready() {
    label=$1
    for _ in $(seq 1 360); do
        if systemctl is-active --quiet netosd && [[ -s /run/netosd.ready ]]; then
            echo "PASS ready: $label revision=$(tr -d '\n' < /run/netosd.ready)"
            return 0
        fi
        unit_result=$(systemctl show netosd -p Result --value 2>/dev/null || true)
        unit_restarts=$(systemctl show netosd -p NRestarts --value 2>/dev/null || true)
        case "$unit_restarts" in ''|*[!0-9]*) unit_restarts=0 ;; esac
        if [[ $unit_result == exit-code || $unit_result == signal || $unit_result == core-dump || $unit_restarts -gt 0 ]]; then
            echo "FAIL readiness crash: $label Result=$unit_result NRestarts=$unit_restarts" >&2
            systemctl status netosd --no-pager || true
            journalctl -u netosd --no-pager -n 100 || true
            return 1
        fi
        sleep 1
    done
    echo "FAIL readiness timeout: $label" >&2
    systemctl status netosd --no-pager || true
    journalctl -u netosd --no-pager -n 100 || true
    return 1
}

assert_clean() {
    label=$1
    systemctl is-active --quiet netosd
    [[ -s /run/netosd.ready ]]
    plan=$(netos plan)
    printf '%s\n' "$plan"
    grep -Fq 'Живая система соответствует конфигурации: применять нечего.' <<< "$plan"
    failed=$(systemctl --failed --no-legend --plain)
    [[ -z "$failed" ]] || { printf 'failed units after %s:\n%s\n' "$label" "$failed" >&2; return 1; }
}

capture_stage() {
    stage=$1
    "$capture" "$work/$stage"
    journalctl -u 'netos*' --since '-15 minutes' --no-pager -q > "$work/$stage-journal.txt" || true
}

install_candidate() {
    NETOS_BINARY_URL="file://$binary" NETOS_VERSION=dev-qa bash "$installer"
}

recover_original() {
    status=$?
    trap - ERR EXIT
    set +e
    if [[ $status -ne 0 ]]; then
        echo "FAIL cycle status=$status; attempting automatic recovery"
        if [[ ! -x /usr/local/bin/netos ]]; then
            install_candidate
        fi
        if [[ -n ${backup:-} && -f $backup && -x /usr/local/bin/netos ]]; then
            /usr/local/bin/netos restore "$backup" --yes
            wait_ready recovery
        fi
        systemctl status netosd --no-pager || true
        journalctl -u 'netos*' --no-pager -n 150 || true
        "$capture" "$work/failure-recovery" || true
    fi
    if [[ -n ${monitor_pid:-} ]]; then kill "$monitor_pid" 2>/dev/null || true; wait "$monitor_pid" 2>/dev/null || true; fi
    exit "$status"
}
trap recover_original ERR EXIT

(trap - ERR EXIT; monitor_loop) >> "$work/monitor.log" 2>&1 &
monitor_pid=$!

echo "STAGE preflight"
assert_clean preflight
capture_stage before

echo "STAGE backup"
backup_output=$(netos backup)
printf '%s\n' "$backup_output"
backup=$(sed -n 's/^Резервная копия создана: //p' <<< "$backup_output" | tail -n 1)
case "$backup" in /var/backups/netos/netos-backup-*.tar.gz) ;; *) echo "unexpected backup path: $backup" >&2; false ;; esac
[[ -f "$backup" && ! -L "$backup" ]] || { echo "backup is not a regular file" >&2; false; }
gzip -t "$backup"
wait_ready post-backup
assert_clean post-backup

echo "STAGE reset"
netos reset --yes --no-backup
wait_ready factory-reset
assert_clean factory-reset
capture_stage factory

echo "STAGE restore after reset"
netos restore "$backup" --yes
wait_ready reset-restore
assert_clean reset-restore
capture_stage reset-restored
"$compare" "$work/before" "$work/reset-restored" "$backup" | tee "$work/reset-compare.txt"

echo "STAGE uninstall"
netos uninstall --yes
[[ ! -e /usr/local/bin/netosd && ! -e /usr/local/bin/netos && ! -e /etc/systemd/system/netosd.service ]]
capture_stage uninstalled

echo "STAGE clean install from verified local artifact"
install_candidate
wait_ready clean-install
assert_clean clean-install
capture_stage clean-installed

echo "STAGE restore original backup after clean install"
netos restore "$backup" --yes
wait_ready final-restore
assert_clean final-restore
capture_stage after
"$compare" "$work/before" "$work/after" "$backup" | tee "$work/final-compare.txt"

echo "STAGE SQLite comparison"
final_backup_output=$(netos backup)
printf '%s\n' "$final_backup_output"
final_backup=$(sed -n 's/^Резервная копия создана: //p' <<< "$final_backup_output" | tail -n 1)
case "$final_backup" in /var/backups/netos/netos-backup-*.tar.gz) ;; *) echo "unexpected final backup: $final_backup" >&2; false ;; esac
gzip -t "$final_backup"
install -d -m 0700 "$work/original-archive" "$work/final-archive"
tar -C "$work/original-archive" -xzf "$backup" var/lib/netos/netos.db
tar -C "$work/final-archive" -xzf "$final_backup" var/lib/netos/netos.db
python3 "$compare_sqlite" \
    "$work/original-archive/var/lib/netos/netos.db" \
    "$work/final-archive/var/lib/netos/netos.db" | tee "$work/sqlite-compare.txt"
wait_ready final-backup
assert_clean final

echo "PASS destructive reset/uninstall/reinstall lifecycle: $work"
trap - ERR EXIT
kill "$monitor_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true

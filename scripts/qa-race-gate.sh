#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 || ! $1 =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "usage: qa-race-gate.sh RUN_ID SOURCE_ARCHIVE" >&2
    exit 2
fi
[[ $(id -u) -eq 0 ]] || { echo "root is required" >&2; exit 1; }
[[ -n ${INVOCATION_ID:-} ]] || { echo "run through systemd-run" >&2; exit 1; }

run_id=$1
archive=$(readlink -f "$2")
case "$archive" in /var/backups/netos/qa-assets-*/qa-race-backend.tar.gz) ;; *) echo "unsafe archive" >&2; exit 1 ;; esac
[[ -f "$archive" && ! -L "$archive" && $(stat -c %u "$archive") == 0 ]] || exit 1

work=/var/backups/netos/qa-race-$run_id
[[ ! -e "$work" ]] || { echo "refusing to overwrite $work" >&2; exit 1; }
install -d -m 0700 "$work" "$work/src"
export GOPATH="$work/gopath"
export GOMODCACHE="$GOPATH/pkg/mod"
export GOCACHE="$work/gocache"
install -d -m 0700 "$GOMODCACHE" "$GOCACHE"
if [[ -n ${NETOS_QA_RACE_CACHE_SEED:-} ]]; then
    seed=$(readlink -f "$NETOS_QA_RACE_CACHE_SEED")
    case "$seed" in /var/backups/netos/qa-race-*) ;; *) echo "unsafe cache seed" >&2; exit 1 ;; esac
    [[ -d "$seed/gopath" && -d "$seed/gocache" && $(stat -c %u "$seed") == 0 ]] || exit 1
    cp -al "$seed/gopath/." "$GOPATH/"
    cp -al "$seed/gocache/." "$GOCACHE/"
fi
exec > >(tee -a "$work/race.log") 2>&1

snapshot() {
    prefix=$1
    dpkg-query -W -f='${binary:Package}\t${Version}\n' | LC_ALL=C sort > "$work/$prefix-packages.tsv"
    apt-mark showmanual | LC_ALL=C sort > "$work/$prefix-manual.txt"
    systemctl show netosd -p ActiveState -p SubState -p Result -p NRestarts > "$work/$prefix-netosd.txt"
    test -s /run/netosd.ready && cat /run/netosd.ready > "$work/$prefix-ready.txt"
}

snapshot_live_files() {
    prefix=$1
    for path in /var/lib/netos/generated/dnsmasq.conf /etc/resolv.conf; do
        label=${path//\//_}
        if [[ -e $path || -L $path ]]; then
            stat -c '%F\t%a\t%u\t%g\t%N' -- "$path" > "$work/$prefix-live$label.stat"
            sha256sum -- "$path" | cut -d' ' -f1 > "$work/$prefix-live$label.sha256"
        else
            echo absent > "$work/$prefix-live$label.stat"
            echo absent > "$work/$prefix-live$label.sha256"
        fi
    done
}

monitor() {
    while :; do
        printf '%s ' "$(date -Is)"
        systemctl show netosd -p ActiveState -p SubState -p Result -p NRestarts --value | tr '\n' ' '
        if [[ -s /run/netosd.ready ]]; then cat /run/netosd.ready; else echo NO_READY; fi
        sleep 2
    done
}

monitor_pid=
swap_active=0
cleanup() {
    status=$?
    trap - EXIT INT TERM
    [[ -z $monitor_pid ]] || { kill "$monitor_pid" 2>/dev/null || true; wait "$monitor_pid" 2>/dev/null || true; }
    cleanup_status=0
    if [[ $swap_active -eq 1 ]]; then
        swapoff -- "$work/race.swap" || cleanup_status=1
        rm -f -- "$work/race.swap"
        swap_active=0
        echo "temporary race swap removed"
    fi
    if [[ -s "$work/added-packages.txt" ]]; then
        mapfile -t added < "$work/added-packages.txt"
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -- "${added[@]}" || cleanup_status=1
    fi
    snapshot_live_files after || cleanup_status=1
    live_drift=0
    for before in "$work"/before-live*; do
        after=${before/before-live/after-live}
        if ! cmp -s "$before" "$after"; then
            echo "FAIL live file changed: ${before##*/}"
            diff -u "$before" "$after" || true
            live_drift=1
            cleanup_status=1
        fi
    done
    if [[ $live_drift -eq 1 ]]; then
        rm -f /run/netosd.ready
        systemctl restart netosd || cleanup_status=1
        for _ in {1..90}; do [[ -s /run/netosd.ready ]] && break; sleep 1; done
    fi
    snapshot after || cleanup_status=1
    cmp -s "$work/before-packages.tsv" "$work/after-packages.tsv" || { echo "FAIL package versions changed"; diff -u "$work/before-packages.tsv" "$work/after-packages.tsv" || true; cleanup_status=1; }
    cmp -s "$work/before-manual.txt" "$work/after-manual.txt" || { echo "FAIL manual package set changed"; diff -u "$work/before-manual.txt" "$work/after-manual.txt" || true; cleanup_status=1; }
    cmp -s "$work/before-netosd.txt" "$work/after-netosd.txt" || { echo "FAIL netosd state changed"; diff -u "$work/before-netosd.txt" "$work/after-netosd.txt" || true; cleanup_status=1; }
    cmp -s "$work/before-ready.txt" "$work/after-ready.txt" || { echo "FAIL ready revision changed"; cleanup_status=1; }
    plan=$(netos plan) || cleanup_status=1
    grep -Fq 'применять нечего' <<< "${plan:-}" || { echo "FAIL final plan"; cleanup_status=1; }
    if [[ $cleanup_status -ne 0 ]]; then exit 1; fi
    exit "$status"
}
trap cleanup EXIT INT TERM

snapshot before
snapshot_live_files before
(trap - EXIT INT TERM; monitor) > "$work/monitor.log" 2>&1 &
monitor_pid=$!

tar -C "$work/src" -xzf "$archive"
cd "$work/src/backend"
go mod verify

DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev shellcheck
snapshot installed
LC_ALL=C comm -13 <(cut -f1 "$work/before-packages.tsv") <(cut -f1 "$work/installed-packages.tsv") > "$work/added-packages.txt"
[[ -s "$work/added-packages.txt" ]] || { echo "gcc installation added no packages" >&2; false; }
command -v gcc
shellcheck "$work/src/scripts/qa-race-gate.sh"

mem_available=$(awk '/MemAvailable:/ {print $2 * 1024}' /proc/meminfo)
swap_total=$(awk '/SwapTotal:/ {print $2 * 1024}' /proc/meminfo)
if (( mem_available + swap_total < 1610612736 )); then
    fallocate -l 1G "$work/race.swap"
    chmod 0600 "$work/race.swap"
    mkswap "$work/race.swap"
    swapon "$work/race.swap"
    swap_active=1
    echo "temporary 1 GiB race swap enabled"
fi

CGO_ENABLED=1 go test -race -p 1 -count=1 ./... | tee "$work/go-test-race.txt"
echo "PASS Linux race gate"

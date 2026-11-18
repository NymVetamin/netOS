#!/bin/bash
set -eu
cd "$(dirname "$0")/../.."
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
# Run the remote transaction inside a temporary tree. A missing candidate
# triggers rollback after all three snapshot entries have been captured.
sed -n "/^set -u$/,/^REMOTE_DEPLOY$/p" scripts/dev-push.sh | sed '$d' |
    sed -e 's|=/usr/local/bin/|="$root"/bin/|' -e 's|=/etc/bash_completion.d/|="$root"/|' \
        -e 's|=/run/|="$root"/|' > "$root/deploy"
export root NETOS_EXPECTED_SHA=unused TMPDIR="$root/snapshots"
mkdir "$root/bin" "$TMPDIR"
printf 'original' > "$root/bin/netosd"
systemctl() { return 1; }
journalctl() { :; }
cp() {
    if [[ $fault == copy && ${*: -1} == "$root/bin/netosd" ]]; then return 1; fi
    command cp "$@"
}
rm() {
    if [[ $fault == remove && ${*: -1} == "$root/bin/netos" ]]; then return 1; fi
    command rm "$@"
}
export -f systemctl journalctl cp rm
for fault in copy remove none; do
    export fault
    if bash "$root/deploy" > "$root/log" 2>&1; then exit 1; fi
    shopt -s nullglob
    snapshots=("$TMPDIR"/*)
    if [[ $fault == none ]]; then
        [[ ${#snapshots[@]} == 0 && $(cat "$root/bin/netosd") == original ]]
    else
        [[ ${#snapshots[@]} == 1 && $(cat "${snapshots[0]}/binary") == original ]]
        grep -F -- "${snapshots[0]}" "$root/log" >/dev/null
        command cp "${snapshots[0]}/binary" "$root/bin/netosd"
        command rm -r -- "${snapshots[0]}"
    fi
done

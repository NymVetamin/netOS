#!/bin/bash
set -eu
cd "$(dirname "$0")/../.."
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
# Run the remote transaction inside a temporary tree.
sed -n "/^set -u$/,/^REMOTE_DEPLOY$/p" scripts/dev-push.sh | sed '$d' |
    sed -e 's|=/usr/local/bin/|="$root"/bin/|' -e 's|=/etc/bash_completion.d/|="$root"/|' \
        -e 's|=/usr/share/bash-completion/completions/|="$root"/lazy/|' -e 's|=/run/|="$root"/|' > "$root/deploy"
export root NETOS_EXPECTED_SHA=unused TMPDIR="$root/snapshots"
export NETOS_CANDIDATE="$root/bin/candidate"
mkdir "$root/bin" "$TMPDIR"
printf 'original' > "$root/bin/netosd"
systemctl() { echo "$*" >> "$root/service-calls"; return 1; }
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
export fault=none
printf 'incomplete transfer' > "$NETOS_CANDIDATE"
NETOS_EXPECTED_SHA=$(printf 'complete transfer' | sha256sum | awk '{print $1}')
if bash "$root/deploy" > "$root/log" 2>&1; then exit 1; fi
grep -F 'SHA-256' "$root/log" >/dev/null
[[ $(cat "$root/bin/netosd") == original && ! -e "$NETOS_CANDIDATE" && ! -e "$root/service-calls" ]]

# Fail activation after the snapshot to exercise the original rollback cases.
chmod() { return 1; }
export -f chmod
for fault in copy remove none; do
    export fault
    printf 'candidate' > "$NETOS_CANDIDATE"
    NETOS_EXPECTED_SHA=$(sha256sum "$NETOS_CANDIDATE" | awk '{print $1}')
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
unset -f chmod

systemctl() {
    if [[ $1 == restart ]]; then echo ready > "$root/netosd.ready"; fi
    return 0
}
export -f systemctl
mkdir -p "$root/lazy"
sha256sum() {
    echo "hash $1" >> "$root/events"
    command sha256sum "$@"
}
export -f sha256sum
for result in fail success; do
    export result
    printf old-eager > "$root/netos"
    printf old-lazy > "$root/lazy/netos"
    cat > "$NETOS_CANDIDATE" <<'EOF'
#!/bin/bash
case "$1" in
    completion) echo completion >> "$root/events"; echo new-completion ;;
    version) echo test ;;
    plan) [[ $result == success ]] && echo 'Живая система соответствует конфигурации: применять нечего.' ;;
esac
EOF
    NETOS_EXPECTED_SHA=$(sha256sum "$NETOS_CANDIDATE" | awk '{print $1}')
    : > "$root/events"
    if [[ $result == fail ]]; then
        if bash "$root/deploy" > "$root/log" 2>&1; then exit 1; fi
        [[ $(cat "$root/netos") == old-eager && $(cat "$root/lazy/netos") == old-lazy ]]
    else
        bash "$root/deploy" > "$root/log" 2>&1
        [[ $(cat "$root/netos") == new-completion && $(cat "$root/lazy/netos") == new-completion ]]
        [[ $(head -n 1 "$root/events") == "hash $NETOS_CANDIDATE" ]]
    fi
done

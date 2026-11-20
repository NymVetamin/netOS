#!/bin/bash
set -eu
cd "$(dirname "$0")/../.."
root=$(mktemp -d)
export root
trap 'rm -rf -- "$root"' EXIT
mkdir -p "$root"/{scripts,bin,lazy,lock,tmp}
sed -e "s|/usr/local/bin/|$root/bin/|g" -e "s|/etc/bash_completion.d/|$root/|g" \
    -e "s|/usr/share/bash-completion/completions/|$root/lazy/|g" \
    -e "s|/run/|$root/|g" scripts/dev-push.sh > "$root/scripts/dev-push.sh"
export TMPDIR="$root/tmp"

wait_for() {
    for ((i=0; i<500; i++)); do
        [[ -e $1 ]] && return 0
        sleep .02
    done
    echo "timed out waiting for $1" >&2
    return 1
}
scp() {
    local target=${3#*:}
    if [[ $PUSH_ID == B ]]; then wait_for "$root/A.uploaded" || return 1; fi
    cp -- "$2" "$target" || return 1
    touch "$root/$PUSH_ID.uploaded"
    if [[ $PUSH_ID == A ]]; then wait_for "$root/B.uploaded" || return 1; fi
    [[ $PUSH_ID != broken ]]
}
ssh() {
    if [[ $2 == *NETOS_EXPECTED_SHA=* ]]; then
        if [[ $PUSH_ID == B ]]; then wait_for "$root/A.restarting" || return 1; fi
        touch "$root/$PUSH_ID.started"
    fi
    bash -c "$2"
}
systemctl() {
    if [[ $1 == restart ]]; then
        touch "$root/$PUSH_ID.restarting"
        echo ready > "$root/netosd.ready"
    fi
    return 0
}
journalctl() { :; }
cp() {
    if [[ $PUSH_ID == B && ${*: -1} == */binary && ! -e $root/A.verified ]]; then
        echo "second deployment took its snapshot before the first finished" >&2
        return 1
    fi
    command cp "$@"
}
export -f wait_for scp ssh systemctl journalctl cp
for id in A B; do
    cat > "$root/$id" <<'EOF'
#!/bin/bash
case "$1" in
    version) touch "$root/$PUSH_ID.verified"; echo BUILD_ID ;;
    completion) echo BUILD_ID ;;
    plan)
        if [[ $PUSH_ID == A ]]; then wait_for "$root/B.started" || exit 1; fi
        echo 'Живая система соответствует конфигурации: применять нечего.' ;;
esac
EOF
    sed -i "s/BUILD_ID/$id/g" "$root/$id"
done
for id in A B; do
    PUSH_ID=$id NETOS_BINARY_FILE="$root/$id" bash "$root/scripts/dev-push.sh" > "$root/$id.log" 2>&1 &
    if [[ $id == A ]]; then first=$!; else second=$!; fi
done
status=0
wait "$first" || status=1
wait "$second" || status=1
if ((status)); then cat "$root"/{A,B}.log >&2; exit 1; fi
for id in A B; do grep -Fq "работает: $id" "$root/$id.log"; done
cmp "$root/B" "$root/bin/netosd"
[[ $(cat "$root/lazy/netos") == B ]]

# Fail after copying all bytes, as an interrupted transfer can leave a file.
if PUSH_ID=broken NETOS_BINARY_FILE="$root/A" bash "$root/scripts/dev-push.sh" > "$root/error.log" 2>&1; then exit 1; fi
cmp "$root/B" "$root/bin/netosd"
[[ $(find "$root/bin" -type f | wc -l) == 1 ]]

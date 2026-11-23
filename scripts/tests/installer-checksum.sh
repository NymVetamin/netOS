#!/bin/bash
set -eu
installer=$(cd "$(dirname "$0")/../.." && pwd)/install.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
TMP="$work/binary"
printf 'netOS checksum fixture\n' > "$TMP"
# Execute the real validation block, stopping before any installation writes.
sed -n '/^    EXPECTED=$(awk /,/^    CANDIDATE="\$TMP"$/p' "$installer" > "$work/check.sh"
[[ -s "$work/check.sh" ]]
die() { printf '%s\n' "$*" >&2; exit 1; }
ok() { :; }
digest=$(sha256sum "$TMP" | awk '{print $1}')
check() {
    local expected=$1 contents=$2 result=0
    printf '%s' "$contents" > "$TMP.sha256"
    (source "$work/check.sh"; [[ "$CANDIDATE" == "$TMP" ]]) > "$work/output" 2>&1 || result=$?
    if [[ "$result" != "$expected" ]]; then
        cat "$work/output" >&2
        echo "checksum case: expected $expected, got $result" >&2
        exit 1
    fi
}
for repeat in 1 2; do
    check 0 "$digest  netosd-linux-amd64"
    check 0 "${digest^^} *netosd-linux-arm64"
    check 0 "$digest"
    check 1 ''
    check 1 "${digest:0:63}"
    check 1 "${digest}0"
    check 1 "g${digest:1}"
    check 1 "$(printf '%064d' 0)"
    check 1 "invalid"$'\n'"$digest  netosd"
    check 1 $'\n'"$digest"
done
printf 'installer checksum validation: PASS\n'

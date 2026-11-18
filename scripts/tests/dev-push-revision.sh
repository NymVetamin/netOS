#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export NETOS_SKIP_WEB=1
unset NETOS_BINARY_FILE
export EXPECTED_REVISION
EXPECTED_REVISION=$(git rev-parse HEAD)

# Exercise the CI fallback without building a binary or contacting a router.
command() {
    if [[ "$*" == "-v go" ]]; then return 1; fi
    builtin command "$@"
}
gh() {
    if [[ "$1 $2" == "run download" ]]; then
        echo "download $3" >&2
        return 1
    fi
    [[ "$1 $2" == "run list" ]] || return 2
    if [[ " $* " != *" --commit $EXPECTED_REVISION "* ]]; then
        echo 41 # Successful build of another commit on the same branch.
    elif [[ "$EXACT_BUILD" == yes ]]; then
        echo 42
    fi
}
scp() { return 1; }
ssh() { return 1; }
export -f command gh scp ssh
for EXACT_BUILD in no yes yes; do
    export EXACT_BUILD
    output=$(./scripts/dev-push.sh 2>&1) && exit 1
    if [[ "$EXACT_BUILD" == no ]]; then
        [[ "$output" == *"$EXPECTED_REVISION"* && "$output" != *"download "* ]]
    else
        [[ "$output" == *"download 42"* ]]
    fi
done

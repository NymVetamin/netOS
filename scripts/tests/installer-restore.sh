#!/bin/bash
set -eu
installer=$(cd "$(dirname "$0")/../.." && pwd)/install.sh
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT

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
if rollback > "$root/second.log" 2>&1; then exit 1; fi
[[ $(cat "$BIN_PATH") == previous && ! -e "$INSTALL_TXN" ]]

#!/bin/bash
set -eu
installer=$(cd "$(dirname "$0")/../.." && pwd)/install.sh
SRC=$(mktemp -d)
trap 'rm -rf -- "$SRC"' EXIT
mkdir -p "$SRC/go/bin" "$SRC/netos/web" "$SRC/netos/backend" "$SRC/tmp"
export SRC
BUILD_VERSION=test
CANDIDATE="$SRC/netosd"
sed -n '/^    CANDIDATE="\$SRC\/netosd"$/,/^    ) || die /p' "$installer" | tail -n +2 > "$SRC/build.sh"
die() { exit 1; }
npm() {
    echo "$1" >> "$SRC/calls"
    [[ "$PWD" == "$SRC/netos/web" && "$FAIL" != "$1" ]]
}
cat > "$SRC/go/bin/go" <<'EOF'
#!/bin/sh
echo go >> "$SRC/calls"
[ "$PWD" = "$SRC/netos/backend" ] || exit 1
case "$FAIL:$GOPROXY" in
    go:*|mirror:https://proxy.golang.org,*) exit 1 ;;
esac
EOF
chmod +x "$SRC/go/bin/go"

check() {
    export FAIL="$1"
    local status=0
    : > "$SRC/calls"
    (source "$SRC/build.sh") || status=$?
    if [[ "$status" != "$2" || "$(paste -sd, "$SRC/calls")" != "$3" ]]; then
        echo "case $1: status=$status, calls=$(paste -sd, "$SRC/calls")" >&2
        exit 1
    fi
}
check ci 1 ci
check run 1 ci,run
rmdir "$SRC/netos/web"
check web 1 ''
mkdir "$SRC/netos/web"
rmdir "$SRC/netos/backend"
check backend 1 ci,run
mkdir "$SRC/netos/backend"
check go 1 ci,run,go,go
check mirror 0 ci,run,go,go
check success 0 ci,run,go
check success 0 ci,run,go

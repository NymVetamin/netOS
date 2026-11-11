#!/usr/bin/env bash
# Build only on the CI/build machine. The router installs the resulting .deb.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:?output directory required}
mkdir -p "$out"
out=$(cd "$out" && pwd)
version=3.1.20260828-1
export SOURCE_DATE_EPOCH=1787914161
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
cd "$root/backend"
test "$(go list -m -f '{{.Version}}' github.com/amnezia-vpn/amneziawg-go/v3)" = v3.1.20260828
for arch in amd64 arm64; do
  stage="$build/$arch"
  mkdir -p "$stage/DEBIAN" "$stage/usr/lib/netos" "$stage/usr/share/doc/netos-amneziawg-go"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
    -ldflags '-s -w -buildid=' -o "$stage/usr/lib/netos/amneziawg-go" ./cmd/netos-amneziawg-go
  cat > "$stage/DEBIAN/control" <<EOF
Package: netos-amneziawg-go
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: netOS maintainers <netos-router@users.noreply.github.com>
Homepage: https://github.com/NymVetamin/netOS
Description: Official AmneziaWG-Go dataplane with the netOS service launcher
 Built from github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828.
 Contains no compiler, system services or automatic network configuration.
EOF
  # Include licenses of every linked module, not unrelated backend dependencies.
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go list -deps -f '{{if .Module}}{{if not .Module.Main}}{{.Module.Dir}}{{end}}{{end}}' \
    ./cmd/netos-amneziawg-go | sort -u | while IFS= read -r module; do
      [ -n "$module" ] || continue
      for license in LICENSE COPYING; do
        if [ -f "$module/$license" ]; then
          printf '\n--- %s / %s ---\n' "${module##*/}" "$license"
          cat "$module/$license"
        fi
      done
    done > "$stage/usr/share/doc/netos-amneziawg-go/copyright"
  find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  dpkg-deb --root-owner-group -Zxz --build "$stage" "$out/netos-amneziawg-go_${version}_${arch}.deb"
done
cd "$out"
sha256sum netos-amneziawg-go_"$version"_*.deb > SHA256SUMS

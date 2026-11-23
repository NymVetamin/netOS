#!/bin/bash
# Full installer exercise in a disposable Debian guest, never on the runner OS.
set -euo pipefail
: "${RUNNER_TEMP:?GitHub runner required}"
: "${NETOS_TEST_BINARY:?prebuilt Linux binary required}"
repo=$(pwd)
test_root=$(mktemp -d "$RUNNER_TEMP/netos-install.XXXXXX")
http_pid=""
cleanup() {
    [ -z "$http_pid" ] || kill "$http_pid" 2>/dev/null || true
    if [ -s "$test_root/qemu.pid" ]; then
        kill "$(cat "$test_root/qemu.pid")" 2>/dev/null || true
    fi
}
trap cleanup EXIT
cd "$test_root"
image=debian-12-genericcloud-amd64.qcow2
base=https://cloud.debian.org/images/cloud/bookworm/latest
curl -fSL --retry 3 "$base/$image" -o "$image"
curl -fSL --retry 3 "$base/SHA512SUMS" -o SHA512SUMS
awk -v image="$image" '$2 == image' SHA512SUMS > image.sha512
test -s image.sha512
sha512sum -c image.sha512
cat image.sha512
qemu-img create -f qcow2 -F qcow2 -b "$test_root/$image" guest.qcow2 12G
ssh-keygen -q -t ed25519 -N '' -f key
cat > user-data <<EOF
#cloud-config
ssh_authorized_keys:
  - $(cat key.pub)
ssh_pwauth: false
EOF
printf 'instance-id: netos-install-test\nlocal-hostname: netos-install-test\n' > meta-data
cloud-localds seed.img user-data meta-data
accel=tcg
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then accel=kvm; fi
qemu-system-x86_64 -machine "accel=$accel" -m 2048 -smp 2 \
    -drive file=guest.qcow2,if=virtio,format=qcow2 \
    -drive file=seed.img,if=virtio,format=raw \
    -netdev user,id=net,hostfwd=tcp:127.0.0.1:10022-:22 -device virtio-net-pci,netdev=net \
    -display none -serial file:console.log -daemonize -pidfile qemu.pid
ssh_args=(-i "$test_root/key" -p 10022 -o BatchMode=yes -o ConnectTimeout=5
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$test_root/known_hosts")
guest() { ssh "${ssh_args[@]}" debian@127.0.0.1 "$@"; }
ready=0
for _ in $(seq 1 90); do
    if guest true 2>/dev/null; then ready=1; break; fi
    sleep 2
done
test "$ready" = 1
guest 'sudo cloud-init status --wait >/dev/null; . /etc/os-release; test "$VERSION_ID" = 12; mawk -W version'
guest 'cat > /tmp/install.sh' < "$repo/install.sh"
mkdir served
cp "$NETOS_TEST_BINARY" served/netosd-linux-amd64
digest=$(sha256sum served/netosd-linux-amd64 | awk '{print $1}')
printf '%064d  netosd-linux-amd64\n' 0 > served/netosd-linux-amd64.sha256
python3 -m http.server 18080 --bind 127.0.0.1 --directory served > http.log 2>&1 &
http_pid=$!
for _ in $(seq 1 20); do
    if curl -fsS http://127.0.0.1:18080/netosd-linux-amd64.sha256 >/dev/null; then break; fi
    sleep 1
done
guest "sudo bash -s" <<'GUEST'
set -euo pipefail
if NETOS_BINARY_URL=http://10.0.2.2:18080/netosd-linux-amd64 bash /tmp/install.sh >/root/install-bad.log 2>&1; then
    echo 'FAIL: invalid checksum accepted'; exit 1
fi
grep -q 'контрольная сумма не совпадает' /root/install-bad.log
test ! -e /usr/local/bin/netosd
echo 'Invalid checksum rejected before binary installation PASS'
GUEST
printf '%s  netosd-linux-amd64\n' "$digest" > served/netosd-linux-amd64.sha256
for mode in fresh repeat; do
    guest "sudo env EXPECTED_SHA=$digest MODE=$mode bash -s" <<'GUEST'
set -euo pipefail
# The installer prints credentials; keep its complete log inside the guest.
if ! NETOS_BINARY_URL=http://10.0.2.2:18080/netosd-linux-amd64 bash /tmp/install.sh >"/root/install-$MODE.log" 2>&1; then
    systemctl show netosd -p ActiveState -p SubState -p NRestarts
    # Only synthetic guest data exists here; still omit credential-bearing lines.
    sed -E '/[Пп]ароль|[Pp]assword|[Tt]oken|[Ss]ecret|[Pp]rivate[Kk]ey/d' \
        "/root/install-$MODE.log" | tail -80
    echo "FAIL: $MODE install (private log retained inside guest)"; exit 1
fi
test "$(sha256sum /usr/local/bin/netosd | awk '{print $1}')" = "$EXPECTED_SHA"
systemctl is-active --quiet netosd
systemctl is-enabled --quiet netosd
test -s /run/netosd.ready
test "$(curl -kfsS --max-time 10 https://127.0.0.1:8443/api/ping)" = '{"ok":true,"service":"netos"}'
echo "Debian12 $MODE install: SHA, service, readiness and API PASS"
GUEST
done

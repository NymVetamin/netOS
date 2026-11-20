#!/bin/bash
# Run under sudo unshare -mn. No installation may advance beyond preflight.
set -euo pipefail
for ns in mnt net; do
    [[ $(readlink "/proc/self/ns/$ns") != "$(readlink "/proc/1/ns/$ns")" ]]
done
installer=$(cd "$(dirname "$0")/../.." && pwd)/install.sh
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
cp "$installer" "$root/install.sh"
mount --make-rprivate /
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /usr/local/bin
mount -t tmpfs tmpfs /var/lib
ip link add brwan type bridge
ip link add port0 type veth peer name ordinary
ip link set port0 master brwan
for dev in brwan port0 ordinary; do ip link set "$dev" up; done
ip addr add 192.0.2.2/24 dev brwan
ip route add default via 192.0.2.1 dev brwan metric 20
mktemp() { return 78; } # First write after the installation checks.
export -f mktemp
check() {
    local expected=$1 rc=0
    /bin/bash "$root/install.sh" >"$root/log" 2>&1 || rc=$?
    [[ $rc == "$expected" ]] || { cat "$root/log"; return 1; }
    if [[ $expected == 1 ]]; then
        grep -q 'мост brwan' "$root/log"
        grep -q 'Порт моста: port0' "$root/log"
        grep -q 'отдельный доступ' "$root/log"
    fi
}
for attempt in 1 2; do
    check 1
    grep -q '192.0.2.2/24' "$root/log"
    [[ ! -e /var/lib/netos ]]
    ip -4 route show default | grep -q 'via 192.0.2.1 dev brwan'
    [[ -e /sys/class/net/brwan/brif/port0 ]]
done
ip() {
    [[ " $* " != *" addr show "* ]] || return 1
    command ip "$@"
}
export -f ip
check 1
unset -f ip
# A minimal image may lack iproute2 until apt runs.
mkdir "$root/minimal"
for cmd in id systemctl uname find wc awk grep cat; do ln -s "$(command -v "$cmd")" "$root/minimal/$cmd"; done
PATH="$root/minimal" check 1
ip addr add 198.51.100.2/24 dev ordinary
ip route add default via 198.51.100.1 dev ordinary metric 10
check 78
PATH="$root/minimal" check 78
ip route del default via 198.51.100.1 dev ordinary
touch /usr/local/bin/netosd
chmod +x /usr/local/bin/netosd
check 1
mkdir /var/lib/netos
echo installed >/var/lib/netos/netos.db
check 78

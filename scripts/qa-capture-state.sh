#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 || "$1" != /var/backups/netos/qa-* ]]; then
    echo "usage: qa-capture-state.sh /var/backups/netos/qa-NAME" >&2
    exit 2
fi

out=$1
if [[ -e "$out" ]]; then
    echo "refusing to overwrite $out" >&2
    exit 1
fi
umask 077
mkdir -p "$out"

have_netos() {
    netos_path=$(command -v netos 2>/dev/null || true)
    [[ -n "$netos_path" && -x "$netos_path" ]]
}

date -Is > "$out/date.txt"
uname -a > "$out/uname.txt"
cp /etc/os-release "$out/os-release.txt"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' | sort > "$out/packages.tsv"
apt-mark showmanual | sort > "$out/packages-manual.txt"
systemctl list-units --all --no-pager --plain > "$out/systemd-units.txt"
systemctl list-unit-files --no-pager --plain > "$out/systemd-unit-files.txt"
systemctl --failed --no-pager --plain > "$out/systemd-failed.txt"

{
    mapfile -t netos_units < <(systemctl list-unit-files 'netos*.service' --no-legend --plain | awk '{print $1}' | sort -u)
    for unit in "${netos_units[@]}"; do
        echo "[$unit]"
        systemctl show "$unit" \
            -p LoadState -p UnitFileState -p ActiveState -p SubState \
            -p Result -p ExecMainStatus -p NRestarts
    done
} > "$out/netos-unit-state.txt"
sed '/^NRestarts=/d' "$out/netos-unit-state.txt" > "$out/netos-unit-health.txt"
for unit in tuned.service systemd-timesyncd.service systemd-resolved.service \
    systemd-networkd.service NetworkManager.service; do
    printf '[%s]\n' "$unit"
    systemctl show "$unit" -p LoadState -p UnitFileState -p ActiveState -p SubState 2>/dev/null || true
done > "$out/host-service-state.txt"

ip -details -statistics link show > "$out/ip-link.txt"
ip -brief link show > "$out/ip-link-brief.txt"
ip -4 address show > "$out/ip-address-v4.txt"
ip -6 address show > "$out/ip-address-v6.txt"
ip -brief address show > "$out/ip-address-brief.txt"
ip -4 rule show > "$out/ip-rule-v4.txt"
ip -6 rule show > "$out/ip-rule-v6.txt"
ip -4 route show table all > "$out/ip-route-v4.txt"
ip -6 route show table all > "$out/ip-route-v6.txt"
iptables-save > "$out/iptables-save.txt"
ip6tables-save > "$out/ip6tables-save.txt"
if command -v ipset >/dev/null 2>&1; then ipset save > "$out/ipset-save.txt"; else echo absent > "$out/ipset-save.txt"; fi
if command -v bridge >/dev/null 2>&1; then bridge -details link show > "$out/bridge-link.txt"; else echo absent > "$out/bridge-link.txt"; fi
ss -lntup > "$out/listeners.txt"
ss -H -lntu | sort > "$out/listeners-stable.txt"
lsmod > "$out/kernel-modules.txt"

{
    while read -r interface; do
        [[ -n "$interface" ]] || continue
        echo "[$interface]"
        tc -s qdisc show dev "$interface" 2>/dev/null || true
        tc -s class show dev "$interface" 2>/dev/null || true
        tc -s filter show dev "$interface" 2>/dev/null || true
    done < <(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
} > "$out/tc-state.txt"
{
    while read -r interface; do
        [[ -n "$interface" ]] || continue
        echo "[$interface]"
        tc qdisc show dev "$interface" 2>/dev/null || true
        tc class show dev "$interface" 2>/dev/null || true
        tc filter show dev "$interface" 2>/dev/null || true
    done < <(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
} > "$out/tc-config.txt"

stat -c 'type=%F mode=%a uid=%u gid=%g target=%N' /etc/resolv.conf > "$out/resolv-stat.txt"
sha256sum /etc/resolv.conf > "$out/resolv-sha256.txt"
cat /etc/resolv.conf > "$out/resolv-content.txt"
hostnamectl --static > "$out/hostname.txt"
timedatectl show --property=Timezone --value > "$out/timezone.txt"

if have_netos; then
    netos render sysctl | awk -F' = ' '/^net\./ {print $1}' | while read -r key; do
        printf '%s = ' "$key"
        sysctl -n "$key"
    done
else
    sysctl net.ipv4.ip_forward net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 \
        net.ipv4.conf.all.src_valid_mark net.ipv4.conf.all.rp_filter
fi > "$out/sysctl-managed.txt"
for interface in /sys/class/net/*; do
    [[ ${interface##*/} == lo ]] && continue
    for field in disable_ipv6 accept_ra autoconf; do
        path="/proc/sys/net/ipv6/conf/${interface##*/}/$field"
        [[ -r "$path" ]] && printf 'net.ipv6.conf.%s.%s = %s\n' "${interface##*/}" "$field" "$(<"$path")"
    done
done | sort > "$out/sysctl-per-interface.txt"

for root in /var/lib/netos /etc/netos /var/log/netos /var/lib/netos-system-baseline; do
    if [[ -e "$root" ]]; then
        find "$root" -xdev -printf '%y\t%m\t%u\t%g\t%s\t%p\n' | sort
    else
        printf 'absent\t%s\n' "$root"
    fi
done > "$out/netos-tree.tsv"

{
    for root in /var/lib/netos /etc/netos /var/log/netos /var/lib/netos-system-baseline; do
        if [[ -e "$root" ]]; then
            find "$root" -xdev -type f -print0
        fi
    done
} | sort -z | xargs -0 -r sha256sum > "$out/netos-files-sha256.txt"

shopt -s nullglob
managed_paths=(
    /etc/sysctl.d/99-netos*.conf
    /etc/modules-load.d/netos.conf
    /etc/iproute2/rt_tables.d/netos*.conf
    /etc/iproute2/rt_protos.d/netos*.conf
    /etc/apt/apt.conf.d/99netos
    /etc/bash_completion.d/netos
    /etc/network/interfaces.d/netos.conf
    /etc/systemd/network/05-netos-*
    /etc/systemd/networkd.conf.d/99-netos.conf
    /etc/systemd/system/netos*.service
    /etc/systemd/system/netosd.service.d/90-hardening.conf
    /etc/systemd/system/systemd-networkd-wait-online.service.d/99-netos.conf
    /etc/NetworkManager/conf.d/99-netos.conf
    /etc/systemd/timesyncd.conf.d/90-netos.conf
    /usr/local/bin/netos /usr/local/bin/netosd
)
for path in "${managed_paths[@]}"; do
    [[ -e "$path" || -L "$path" ]] || continue
    stat -c '%F\t%a\t%u\t%g\t%s\t%n\t%N' "$path"
    [[ -f "$path" && ! -L "$path" ]] && sha256sum "$path"
done > "$out/managed-system-files.txt"

if have_netos; then
    netos version > "$out/netos-version.txt"
    netos status > "$out/netos-status.txt" 2>&1 || true
    netos plan > "$out/netos-plan.txt" 2>&1 || true
    render_list=$(netos render --list)
    mapfile -t render_artifacts <<< "$render_list"
    for artifact in "${render_artifacts[@]}"; do
        [[ -n "$artifact" ]] || continue
        if netos render "$artifact" > "$out/render-$artifact.txt" 2>/dev/null; then
            sha256sum "$out/render-$artifact.txt" >> "$out/render-sha256.txt"
        else
            rm -f "$out/render-$artifact.txt"
        fi
    done
else
    echo absent > "$out/netos-version.txt"
fi

journalctl -u 'netos*' --since '-2 hours' --no-pager -q > "$out/netos-journal.txt" || true
sha256sum "$out"/* > "$out/manifest.sha256"

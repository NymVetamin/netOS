#!/bin/bash
set -euo pipefail

# Integration-only packages must not start their distribution services on the
# live router: netOS owns those listeners and starts isolated test units itself.
if [[ -e /usr/sbin/policy-rc.d ]]; then
    echo "refusing to replace existing /usr/sbin/policy-rc.d" >&2
    exit 1
fi

cleanup_policy() {
    rm -f /usr/sbin/policy-rc.d
}
trap cleanup_policy EXIT

printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ifupdown \
    ppp \
    pppoe \
    xl2tpd \
    iperf3 \
    strongswan \
    strongswan-swanctl \
    charon-systemd \
    charon-cmd \
    libstrongswan-standard-plugins \
    libcharon-extauth-plugins \
    openconnect \
    hostapd \
    iw \
    kea-dhcp4-server

systemctl is-active netosd
systemctl --failed --no-pager --plain

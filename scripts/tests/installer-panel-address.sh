#!/bin/bash
set -euo pipefail
installer=$(cd "$(dirname "$0")/../.." && pwd)/install.sh
summary=$(sed -n '/^    PANEL_IP=/,/^    echo .*PANEL_PORT/p' "$installer")
export B='' R='' PANEL_PORT=9443
hostname() { echo router-test; }
ip() {
    [[ "$*" == "-4 -o addr show scope global" ]] || return 1
    awk -v n="$rows" 'BEGIN {
        if (n > 0) print "2: eth0 inet 192.0.2.42/24"
        for (i=1; i<n; i++) print "3: eth1 inet 198.51.100.1/24"
    }'
    return "$ip_status"
}
export -f ip hostname
export rows ip_status=0
for rows in 1 100000 0 100000; do
    result=$(bash -euo pipefail -c "$summary")
    host=192.0.2.42
    if (( rows == 0 )); then host=router-test; fi
    [[ "$result" == *"https://$host:9443" ]]
done
ip_status=23
rc=0
result=$(bash -euo pipefail -c "$summary") || rc=$?
[[ $rc == 23 && -z "$result" ]]

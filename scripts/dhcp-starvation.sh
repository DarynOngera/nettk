#!/usr/bin/env bash
# Phase 6 (M22) starvation row: exhaust a small DHCP pool and confirm the
# server stops handing out leases rather than over-subscribing it.
#
#   sudo lab/up.sh dhcp1
#   sudo lab/svc.sh dhcp starve        # restart dhcpd with 10.0.6.100-109 only
#   sudo scripts/dhcp-starvation.sh
#
# The script starts dhcpd itself (via lab/svc.sh dhcp starve) with a 10-address
# pool, then runs dhcpc 12 times with *distinct* chaddrs. Replies are taken off
# the wire with the broadcast flag set (the addresses are not ours, so unicast
# frames addressed to those MACs would not survive the interface MAC filter).
#
# Expected: exactly 10 leases, then DISCOVERs go unanswered. Bounded at 12 runs.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$root/lab/lib.sh"
nt_require_root

topo=$(cat "$NT_STATE" 2>/dev/null || true)
if [[ $topo != dhcp1 ]]; then
    echo "this script expects the dhcp1 topology (run: sudo lab/up.sh dhcp1 --force)"
    exit 2
fi

bin="$root/build/asan/bin/dhcpc"
[[ -x $bin ]] || bin="$root/build/release/bin/dhcpc"
[[ -x $bin ]] || { echo "no dhcpc binary (run: make BUILD=asan all)"; exit 2; }
command -v dnsmasq >/dev/null 2>&1 || { echo "dnsmasq not installed"; exit 2; }

runs=12
pool=10
# The rogue must not answer; stop every dnsmasq, then start the small pool.
nt_ex rogue pkill -x dnsmasq 2>/dev/null || true
"$root/lab/svc.sh" dhcp starve >/dev/null 2>&1
sleep 1

granted=0
declare -a ips=()
for i in $(seq 1 "$runs"); do
    mac=$(printf '02:00:00:00:0a:%02x' "$i")
    xid=$(printf '0x%08x' "$((0x1000 + i))")
    out=$(nt_ex c1 env NT_LAB=1 "$bin" -i eth0 --broadcast --chaddr "$mac" --xid "$xid" \
          --timeout 4 2>&1)
    if grep -q 'lease_valid=1' <<<"$out"; then
        ip=$(grep -oE 'ip=[0-9.]+' <<<"$out" | grep -oE '[0-9.]+$')
        granted=$((granted+1))
        ips+=("$ip")
        echo "  client $i ($mac): $ip"
    else
        echo "  client $i ($mac): no lease ($(grep -oE 'no OFFER[^\"]*' <<<"$out" | head -1))"
    fi
done

"$root/lab/svc.sh" dhcp down >/dev/null 2>&1 || true

echo
echo "starvation: $granted/$runs clients got a lease, pool size $pool"
if [[ $granted -eq $pool ]]; then
    echo "ok: the pool was exhausted at exactly $pool leases; later clients were refused"
    exit 0
fi
echo "FAIL: expected exactly $pool leases" >&2
exit 1

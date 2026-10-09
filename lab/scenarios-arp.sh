#!/usr/bin/env bash
# M7 lab checks for `arp`: honest resolve, hostile-reply rejection, and the
# sender-0.0.0.0 probe not polluting the target's neighbour cache.
# Runs on the `bridge3` topology (all hosts share one L2 segment).
#
# usage: sudo lab/scenarios-arp.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$here/lib.sh"
nt_require_root

topo=$(cat "$NT_STATE" 2>/dev/null || true)
if [[ $topo != bridge3 ]]; then
    echo "this scenario script expects the bridge3 topology (run: sudo lab/up.sh bridge3 --force)"
    exit 2
fi

bin="$root/build/asan/bin/arp"
[[ -x $bin ]] || bin="$root/build/release/bin/arp"
[[ -x $bin ]] || { echo "no arp binary (run: make BUILD=asan all)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not installed"; exit 2; }

target=10.0.0.99
h2mac=02:00:00:00:00:02
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }

cleanup() {
    nt_ex h2 ip addr del 10.0.0.55/24 dev eth0 2>/dev/null || true
    nt_ex h3 ip addr del 10.0.0.55/24 dev eth0 2>/dev/null || true
}
trap cleanup EXIT

# resolve_addr <mode> -> prints any "Unicast reply ..." lines we accepted
resolve_addr() {
    local mode=$1
    : >/tmp/nt-arp-resp.log
    nt_ex h2 python3 "$root/py/arp_responders.py" eth0 \
        --target "$target" --mode "$mode" --count 1 --timeout 8 \
        >/tmp/nt-arp-resp.log 2>&1 &
    local pid=$!
    for _ in $(seq 1 80); do
        grep -q '^ready$' /tmp/nt-arp-resp.log 2>/dev/null && break
        sleep 0.1
    done
    sleep 0.5
    nt_ex h1 env NT_LAB=1 "$bin" -i eth0 -c1 -W2000 "$target" 2>&1 \
        | grep 'Unicast reply' || true
    wait "$pid" 2>/dev/null || true
}

dump_resp() { sed 's/^/      resp: /' /tmp/nt-arp-resp.log; }

# honest reply is accepted and shows h2's MAC
out=$(resolve_addr correct)
if [[ $out == *"$h2mac"* ]]; then ok "honest reply accepted ($h2mac)"
else bad "honest reply accepted"; echo "$out" | sed 's/^/      /'; dump_resp; fi

# hostile replies are rejected
for mode in wrong-sender-ip wrong-eth-src wrong-target; do
    out=$(resolve_addr "$mode")
    if [[ -z $out ]]; then ok "rejected $mode"
    else bad "rejected $mode"; echo "$out" | sed 's/^/      /'; dump_resp; fi
done

# duplicate honest reply is counted, not double-accepted
out=$(resolve_addr dup)
if [[ $(printf '%s\n' "$out" | grep -c 'Unicast reply') -eq 1 ]]; then
    ok "duplicate reply accepted once"
else
    bad "duplicate reply accepted once"; echo "$out" | sed 's/^/      /'
fi

# probe with sender 0.0.0.0 resolves but leaves no 0.0.0.0 neighbour on h2
nt_ex h2 ip neigh flush dev eth0 2>/dev/null || true
out=$(nt_ex h1 env NT_LAB=1 "$bin" -i eth0 --probe -c1 -W700 10.0.0.2 2>&1 | grep 'Unicast reply' || true)
if [[ $out == *"$h2mac"* ]]; then ok "probe reply accepted"
else bad "probe reply accepted"; echo "$out" | sed 's/^/      /'; fi
if nt_ex h2 ip neigh show dev eth0 | grep -q '^0.0.0.0'; then
    bad "probe did not create a 0.0.0.0 cache entry"
else
    ok "probe did not create a 0.0.0.0 cache entry"
fi

# duplicate IP: two hosts answer for 10.0.0.55 -> scan flags a conflict
nt_ex h2 ip addr add 10.0.0.55/24 dev eth0 2>/dev/null || true
nt_ex h3 ip addr add 10.0.0.55/24 dev eth0 2>/dev/null || true
sleep 0.3
out=$(nt_ex h1 env NT_LAB=1 "$bin" scan -i eth0 --rate 200 10.0.0.0/24 2>&1)
if printf '%s\n' "$out" | grep -q '^10.0.0.55 is-at .* CONFLICT'; then
    ok "scan flags duplicate-IP conflict"
else
    bad "scan flags duplicate-IP conflict"; echo "$out" | sed 's/^/      /'
fi
cleanup

echo; echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]

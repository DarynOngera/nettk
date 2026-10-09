#!/usr/bin/env bash
# M6 lab scenarios for traceroute error annotations, on the `line4` topology.
# Mutates only inside the nt-* namespaces and restores state on exit.
#
# usage: sudo lab/scenarios-traceroute.sh
#
#   !N  r1 has no route to 10.0.2.0/24        -> net unreachable from 10.0.1.1
#   !X  r1 rejects forwarded probes (nft)     -> admin prohibited from 10.0.1.1
#   !F  r1/e2 MTU 1400 + DF probe (-s 1400)   -> frag needed, mtu=1400
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$here/lib.sh"
nt_require_root

topo=$(cat "$NT_STATE" 2>/dev/null || true)
if [[ $topo != line4 ]]; then
    echo "this scenario script expects the line4 topology (run: sudo lab/up.sh line4 --force)"
    exit 2
fi

bin="$root/build/asan/bin/traceroute"
[[ -x $bin ]] || bin="$root/build/release/bin/traceroute"
[[ -x $bin ]] || { echo "no traceroute binary (run: make BUILD=asan all)"; exit 2; }

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }

run() { nt_ex h1 env NT_LAB=1 "$bin" -n -W1000 -m3 "$@" 2>&1; }

restore() {
    nt_ex r1 ip route replace 10.0.2.0/24 via 10.0.9.2 2>/dev/null || true
    nt_ex r1 ip link set e2 mtu 1500 2>/dev/null || true
    nt_ex r1 nft delete table ip ntintest 2>/dev/null || true
    nt_ex h1 ip route flush cache 2>/dev/null || true
}
trap restore EXIT

# --- !N: no route on the first router -----------------------------------------
nt_ex r1 ip route del 10.0.2.0/24 via 10.0.9.2 2>/dev/null || true
out=$(run 10.0.2.2)
if [[ $out == *"10.0.1.1"* && $out == *"!N"* ]]; then
    ok "!N from the router with no route"
else
    bad "!N from the router with no route"; echo "$out" | sed 's/^/      /'
fi
restore

# --- !X: admin-prohibited by a filter on the first router ----------------------
nt_ex r1 nft add table ip ntintest
nt_ex r1 nft add chain ip ntintest ntfwd '{ type filter hook forward priority 0; }'
nt_ex r1 nft add rule ip ntintest ntfwd udp dport 33434-33445 \
    reject with icmp type admin-prohibited
out=$(run 10.0.2.2)
if [[ $out == *"10.0.1.1"* && $out == *"!X"* ]]; then
    ok "!X from a rejecting filter"
else
    bad "!X from a rejecting filter"; echo "$out" | sed 's/^/      /'
fi
nt_ex r1 nft delete table ip ntintest
restore

# --- !F: DF probe larger than the next-hop MTU ---------------------------------
# Flush h1's PMTU cache: a previous run cached the 1400 exception, which would fail
# the very first DF send locally (EMSGSIZE) instead of yielding !F from r1.
nt_ex h1 ip route flush cache 2>/dev/null || true
nt_ex r1 ip link set e2 mtu 1400
out=$(run -M do -s 1400 10.0.2.2)
if [[ $out == *"!F"* && $out == *"mtu=1400"* ]]; then
    ok "!F with next-hop mtu"
else
    bad "!F with next-hop mtu"; echo "$out" | sed 's/^/      /'
fi
restore

echo; echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]

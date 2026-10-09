#!/usr/bin/env bash
# M11 lab experiment: ARP poison one victim from a third host, watch arpmon catch
# it, confirm the mapping is restored on exit, and test a static-neighbour defence.
# Runs on `bridge3` (h1 victim 10.0.0.1, h2 owns 10.0.0.2, h3 attacker).
#
# usage: sudo lab/scenarios-spoof.sh
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

bin="$root/build/asan/bin"
[[ -x $bin/arpspoof ]] || bin="$root/build/release/bin"
[[ -x $bin/arpspoof && -x $bin/arpmon ]] || { echo "build first: make BUILD=asan all"; exit 2; }

h3mac=02:00:00:00:00:03
victim=10.0.0.1
spoof=10.0.0.2
ns_h1=$(nt_ns h1)
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }

neigh_mac() { nt_ex h1 ip neigh show "$spoof" dev eth0 2>/dev/null \
    | awk '/lladdr/{for(i=1;i<=NF;i++) if($i=="lladdr") print tolower($(i+1))}' | head -1; }

# populate h1's cache with h2's real MAC
nt_ex h1 ping -c1 -W1 "$spoof" >/dev/null 2>&1 || true
real=$(neigh_mac)
[[ -n $real ]] && ok "h1 has a cached binding for $spoof ($real)" \
              || bad "h1 has no cached binding for $spoof"

# monitor on the victim
timeout 6 ip netns exec "$ns_h1" env NT_LAB=1 "$bin/arpmon" -i eth0 \
    >/tmp/nt-arpmon.out 2>&1 &
mon=$!
sleep 0.5

# arpmon must see the honest binding before the poison, or the first spoofed
# reply is just the first sighting of that IP and binding-change cannot fire.
nt_ex h1 ip neigh flush all 2>/dev/null || true
nt_ex h1 ping -c1 -W1 "$spoof" >/dev/null 2>&1 || true
sleep 0.2

# poison for ~5s then self-restore
nt_ex h3 env NT_LAB=1 "$bin/arpspoof" -i eth0 -t "$victim" -s "$spoof" -n 25 -p 200 \
    >/tmp/nt-arpspoof.out 2>&1 &
atk=$!
sleep 1.5

poisoned=$(neigh_mac)
if [[ $poisoned == "$h3mac" ]]; then ok "victim cache poisoned to attacker MAC"
else bad "victim cache poisoned (got '$poisoned', want $h3mac)"; fi

if grep -q 'ALERT binding-change' /tmp/nt-arpmon.out; then ok "arpmon detected a binding change"
else bad "arpmon detected a binding change"; sed 's/^/      /' /tmp/nt-arpmon.out; fi

wait "$atk" 2>/dev/null || true
sleep 0.5
restored=$(neigh_mac)
if [[ $restored == "$real" ]]; then ok "cache restored to the real MAC on exit"
else bad "cache restored (got '$restored', want $real)"; fi

wait "$mon" 2>/dev/null || true

# static permanent neighbour resists the poison
nt_ex h1 ip neigh replace "$spoof" lladdr "$real" dev eth0 nud permanent
nt_ex h3 env NT_LAB=1 "$bin/arpspoof" -i eth0 -t "$victim" -s "$spoof" -n 8 -p 150 \
    >/dev/null 2>&1
held=$(neigh_mac)
if [[ $held == "$real" ]]; then ok "static permanent neigh resisted poisoning"
else bad "static permanent neigh resisted (got '$held', want $real)"; fi
nt_ex h1 ip neigh del "$spoof" dev eth0 2>/dev/null || true

echo; echo "passed=$pass failed=$fail"
echo "note: with ip_forward=1 on h3 the victim still routes through the attacker (MITM);"
echo "      static/permanent entries, arp_ignore/arp_accept and arpmon are the defences."
[[ $fail -eq 0 ]]

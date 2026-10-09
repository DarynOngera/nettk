#!/usr/bin/env bash
# M9 lab checks for `ndp`: honest resolve accepted, and Advertisements with
# hop limit 64, a wrong target, or a bad checksum rejected (RFC 4861 7.1.1).
# Runs on the `basic` topology (h1 - rtr - h2, IPv6 fd00:1::/64 / fd00:2::/64).
#
# usage: sudo lab/scenarios-ndp.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$here/lib.sh"
nt_require_root

topo=$(cat "$NT_STATE" 2>/dev/null || true)
if [[ $topo != basic ]]; then
    echo "this scenario script expects the basic topology (run: sudo lab/up.sh basic --force)"
    exit 2
fi

bin="$root/build/asan/bin/ndp"
[[ -x $bin ]] || bin="$root/build/release/bin/ndp"
[[ -x $bin ]] || { echo "no ndp binary (run: make BUILD=asan all)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not installed"; exit 2; }

target=fd00:1::99
rtrmac=02:00:00:00:01:01
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }

resolve6() {
    local mode=$1
    : >/tmp/nt-ndp-resp.log
    nt_ex rtr python3 "$root/py/ndp_responders.py" r1 \
        --target "$target" --mode "$mode" --count 1 --timeout 8 \
        >/tmp/nt-ndp-resp.log 2>&1 &
    local pid=$!
    for _ in $(seq 1 80); do
        grep -q '^ready$' /tmp/nt-ndp-resp.log 2>/dev/null && break
        sleep 0.1
    done
    sleep 0.5
    nt_ex h1 env NT_LAB=1 "$bin" -i eth0 -c1 -W2000 "$target" 2>&1 \
        | grep 'is-at' || true
    wait "$pid" 2>/dev/null || true
}

dump_resp() { sed 's/^/      resp: /' /tmp/nt-ndp-resp.log; }

out=$(resolve6 correct)
if [[ $out == *"$rtrmac"* ]]; then ok "honest NA accepted ($rtrmac)"
else bad "honest NA accepted"; echo "$out" | sed 's/^/      /'; dump_resp; fi

for mode in hop64 wrong-target bad-checksum; do
    out=$(resolve6 "$mode")
    if [[ -z $out ]]; then ok "rejected $mode"
    else bad "rejected $mode"; echo "$out" | sed 's/^/      /'; dump_resp; fi
done

echo; echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]

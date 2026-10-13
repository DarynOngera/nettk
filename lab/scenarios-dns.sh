#!/usr/bin/env bash
# Phase 5 (M12-M15) lab rows: the stub resolver and the spoof lesson.
# Runs on the `dnslab` topology with the DNS servers up:
#
#   sudo lab/up.sh dnslab
#   sudo lab/svc.sh dns up          # or dns up-py for the python fallback
#   sudo lab/scenarios-dns.sh
#
# Rows:
#   M12/M14  dnsq --iter walks . -> test. -> example.test. and returns A 10.0.5.200
#   M13      bigtxt forces TC, dnsq retries over TCP (tcp_fallback=1)
#   M15      evil races an injected answer; --weak (predictable id, fixed port)
#            is the losing config, the default (random id + port) rejects it.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$here/lib.sh"
nt_require_root

topo=$(cat "$NT_STATE" 2>/dev/null || true)
if [[ $topo != dnslab ]]; then
    echo "this scenario script expects the dnslab topology (run: sudo lab/up.sh dnslab --force)"
    exit 2
fi

bin="$root/build/asan/bin/dnsq"
[[ -x $bin ]] || bin="$root/build/release/bin/dnsq"
[[ -x $bin ]] || { echo "no dnsq binary (run: make BUILD=asan all)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not installed"; exit 2; }

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
info(){ echo "info  $1"; }

# M12/M14: full iterative walk from the root
out=$(nt_ex c1 env NT_LAB=1 "$bin" -s 10.0.5.1 --iter -t A www.example.test 2>&1)
echo "$out" | sed 's/^/      /'
if grep -q '^answer www.example.test .* A 10.0.5.200' <<<"$out"; then
    ok "M14 iterative walk: A 10.0.5.200 after two referrals"
else
    bad "M14 iterative walk (expected A 10.0.5.200)"
fi

# M13: UDP truncation must fall back to TCP
out=$(nt_ex c1 env NT_LAB=1 "$bin" -s 10.0.5.1 --iter --edns 512 -t TXT bigtxt.example.test 2>&1)
if grep -q 'tcp_fallback=1' <<<"$out" && grep -q '^answer bigtxt.example.test' <<<"$out"; then
    ok "M13 TC=1 fell back to TCP and returned the full TXT"
else
    bad "M13 TC -> TCP fallback"
    echo "$out" | sed 's/^/      /'
fi

# M15: an OFF-PATH attacker sprays forged replies for a guessed (id, port).
# The client's source port must be the one being sprayed for the race to land.
spray() { # weak(0|1) -> prints the address the client accepted (66 forged / 200 honest)
    local weak=$1 flag="" got=""
    [[ $weak == 1 ]] && flag="--weak"
    nt_ex evil python3 "$root/py/dns_spoof.py" eth0 \
        --server 10.0.5.3 --client 10.0.5.10 --answer 10.0.5.66 \
        --mode blind --client-port 53053 --id-start 1 --id-count 4 \
        --count 6000 >/tmp/nt-dns-spoof.log 2>&1 &
    local pid=$!
    for _ in $(seq 1 40); do
        grep -q '^ready' /tmp/nt-dns-spoof.log 2>/dev/null && break
        sleep 0.1
    done
    sleep 0.2
    for _ in $(seq 1 25); do
        got=$(nt_ex c1 env NT_LAB=1 "$bin" $flag -s 10.0.5.3 -T2 -t A www.example.test 2>/dev/null \
              | grep -oE '10\.0\.5\.(66|200)' | head -1)
        [[ -n $got ]] && break
    done
    wait "$pid" 2>/dev/null || true
    echo "$got"
}

forged=$(spray 1)
info "M15 --weak (id from 1, fixed port 53053), blind spray: accepted=$forged"
if [[ $forged == 10.0.5.66 ]]; then
    ok "M15 --weak is spoofable off-path: predictable id + fixed port give the attacker both"
else
    info "M15 --weak race lost this run (nondeterministic); rerun to observe"
fi

forged=$(spray 0)
info "M15 default (random id, random port), same blind spray: accepted=$forged"
if [[ $forged != 10.0.5.66 ]]; then
    ok "M15 blind spoof rejected with a random id/port (RFC 5452 entropy holds)"
else
    bad "M15 blind spoof accepted despite random id/port"
fi

echo
echo "scenarios-dns: $pass passed, $fail failed"
[[ $fail -eq 0 ]]

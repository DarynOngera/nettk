#!/usr/bin/env bash
# M15 (unprivileged half): the transaction-id check in nt_dns_match, run on
# loopback. py/dns_guess.py owns 127.0.0.1:5305 and answers a query with a
# *guessed* id instead of the one it received:
#
#   * `dnsq --weak` uses id 1 for its first ask, so the guess lands
#     -> the forged answer is accepted (the documented weakness);
#   * `dnsq` uses getrandom(2) for the id, so the guess is dropped
#     -> the client counts `ignored`, then `timeout`, and gets no answer.
#
# The privileged half (a real off-path attacker on the dnslab bridge) lives in
# lab/scenarios-dns.sh and needs root.
#
#   usage: scripts/dns-spoof-demo.sh [dnsq-binary]
set -euo pipefail

dnsq=${1:-build/asan/bin/dnsq}
addr=127.0.0.1
port=5305
name=www.example.test

[[ -x $dnsq ]] || { echo "no dnsq at $dnsq (run: make all)" >&2; exit 2; }
export NT_LAB=1

fails=0

# ask <label> <flags...>: serve one guessed-id reply, run dnsq, print the
# server's view and the client's output.
ask() {
    local label=$1; shift
    : >/tmp/nt-dns-guess.log
    python3 py/dns_guess.py --addr "$addr" --port "$port" --guess-id 1 \
        --answer 10.0.5.66 --count 3 >>/tmp/nt-dns-guess.log 2>&1 &
    local gpid=$!
    local i
    for i in $(seq 1 60); do
        grep -q '^ready' /tmp/nt-dns-guess.log 2>/dev/null && break
        sleep 0.05
    done
    "$dnsq" "$@" -s "$addr" -p "$port" -T2 "$name" >/tmp/nt-dns-client.out 2>&1 || true
    wait "$gpid" 2>/dev/null || true
    echo "      $(grep -E 'received id|sent ' /tmp/nt-dns-guess.log | tr '\n' ' ')"
}

# --- weak mode: predictable id 1 meets the guess -------------------------
ask weak --weak
if grep -q 'answer www.example.test .* 10\.0\.5\.66' /tmp/nt-dns-client.out; then
    echo "ok   --weak accepted the forged answer (id 1 is guessable)"
else
    echo "FAIL --weak did not accept the forged answer"
    sed 's/^/      /' /tmp/nt-dns-client.out
    fails=$((fails + 1))
fi

# --- default mode: random id, the same guess is dropped ------------------
ask default
out=$(cat /tmp/nt-dns-client.out)
real=$(grep -oE 'received id=0x[0-9a-f]+' /tmp/nt-dns-guess.log | head -1 | sed 's/.*0x//')
if grep -qE 'ignored=[1-9]' <<<"$out" && grep -q 'timeout=1' <<<"$out" \
   && [[ ${#real} -eq 4 && $real != 0001 ]]; then
    echo "ok   default rejected the guessed id (real id=0x$real, ignored>0, timeout=1)"
else
    echo "FAIL default mode did not drop the guessed id"
    sed 's/^/      /' /tmp/nt-dns-client.out
    fails=$((fails + 1))
fi

if [[ $fails -eq 0 ]]; then
    echo "ok: M15 id-check demo passes (weak is spoofable, random id is not)"
else
    echo "FAIL: $fails check(s) failed" >&2
    exit 1
fi

#!/usr/bin/env bash
# Phase 4, sub-phase 4 lab checks for ncx/echod/sniff --tcp-trace.
# Runs on the `basic` topology (h1 <-> rtr <-> h2 over 10.0.1.0/24 + fd00:1::/64):
#
#   sudo lab/up.sh basic --force
#   sudo lab/scenarios-sockets.sh
#
# Every row is bounded (ncx -w, echod --idle, tcpdump -c, per-row sleeps) and
# stays inside the nt-* namespaces via lab/ex. Rows print their expectation
# first, like the predict questions in the phase docs.
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

ncx="$root/build/asan/bin/ncx"
echod="$root/build/asan/bin/echod"
sniff="$root/build/asan/bin/sniff"
for b in "$ncx" "$echod" "$sniff"; do
    [[ -x $b ]] || { echo "missing $b (run: make BUILD=asan all)"; exit 2; }
done
command -v tcpdump >/dev/null 2>&1 || { echo "tcpdump not installed"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not installed"; exit 2; }

SRV=10.0.1.1   # rtr, next to h1 on the 10.0.1.0/24 link
PORT=9000
SRV6=fd00:1::1
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }

EP=""
CAPS=()

echo_start() { # echo_start [echod args...] -- echod on rtr, backgrounded
    nt_ex rtr env NT_LAB=1 "$echod" --bind "$SRV" --port "$PORT" "$@" \
        >/tmp/nt-sock-echod.log 2>&1 &
    EP=$!
    sleep 0.4
}
echo_stop() {
    if [[ -n $EP ]]; then
        kill "$EP" 2>/dev/null || true
        wait "$EP" 2>/dev/null || true
        EP=""
    fi
}
cap_start() { # cap_start <tag> <iface> <count>
    local tag=$1 iface=$2 cnt=$3
    CAPS+=("$tag")
    : >"/tmp/nt-sock-$tag.pcap"
    nt_ex rtr tcpdump -i "$iface" -c "$cnt" -w "/tmp/nt-sock-$tag.pcap" \
        >/dev/null 2>&1 &
}
cap_stop_all() {
    local tag
    for tag in "${CAPS[@]}"; do
        nt_ex rtr pkill -x tcpdump 2>/dev/null || true
    done
    CAPS=()
    sleep 0.3
}
cleanup() {
    echo_stop
    cap_stop_all
}
trap cleanup EXIT

echo "== row 0: binaries and topology"
if nt_ex rtr ip -4 addr show r1 | grep -q "10.0.1.1/24"; then ok "basic topology up (rtr 10.0.1.1/24)"; else bad "topology"; fi

echo; echo "== row 1: connect -> accept, three views agree"
cap_start r1 r1 12
echo_start --idle 5
nt_ex h1 sh -c "printf 'row1' | env NT_LAB=1 $ncx -N -w3 $SRV $PORT" \
    >/tmp/nt-sock-row1.out 2>&1
rc=$?
sleep 0.4
cap_stop_all
if [[ $rc -eq 0 && $(cat /tmp/nt-sock-row1.out) == row1 ]]; then
    ok "row1: echo returned"
else
    bad "row1: echo returned (rc=$rc out=$(cat /tmp/nt-sock-row1.out))"
fi
echo_stop
grep -o 'accepted=[0-9]* refused=[0-9]*' /tmp/nt-sock-echod.log \
    | sed 's/^/      echod: /'
syns=$(tcpdump -nn -r /tmp/nt-sock-r1.pcap 'tcp' 2>/dev/null | grep -c 'Flags \[S')
if [[ $syns -ge 2 ]]; then
    ok "row1: capture shows handshake (SYN+SYN/ACK=$syns)"
else
    bad "row1: capture shows handshake"; tcpdump -nn -r /tmp/nt-sock-r1.pcap 2>/dev/null | sed 's/^/      /' | head -6
fi
echo "      sniff --tcp-trace on the same pcap:"
"$sniff" -r /tmp/nt-sock-r1.pcap --tcp-trace 2>/dev/null | sed 's/^/        /' | head -4

echo; echo "== row 2: TIME_WAIT when the server closes first"
echo "      predict: SERVER side ends in TIME_WAIT for ~60 s (2*MSL); it sent the first FIN"
echo_start --idle 1
nt_ex h1 python3 "$root/py/slowclient.py" --mode idle --host "$SRV" --port "$PORT" \
    --seconds 4 >/tmp/nt-sock-row2.log 2>&1 &
CP=$!
sleep 3    # echod idle timer (1 s) closes the idle conn; server sends FIN first
echo "      (server should now be in FIN_WAIT_2 - client has not closed yet)"
nt_ex rtr ss -tan state fin-wait-2 2>/dev/null | grep -q ":$PORT " \
    && echo "      observed: FIN_WAIT_2 (client still open)" || echo "      observed: no FIN_WAIT_2 (timing)"
wait "$CP" 2>/dev/null || true   # client closes now -> server FIN_WAIT_2 -> TIME_WAIT
sleep 0.3
if nt_ex rtr ss -tan state time-wait 2>/dev/null | grep -q ":$PORT "; then
    ok "row2: server side in TIME_WAIT (active closer)"
else
    bad "row2: server side in TIME_WAIT"; nt_ex rtr ss -tan 2>/dev/null | grep ":$PORT " | sed 's/^/      /'
fi
nt_ex rtr ss -tan state established 2>/dev/null | grep -q ":$PORT " \
    && bad "row2: conn still established" || ok "row2: nothing left established"
nt_ex rtr ss -tan state time-wait 2>/dev/null | grep ":$PORT " | sed 's/^/      /'
echo_stop

echo; echo "== row 3: --linger0 turns the idle close into an RST"
echo "      predict: SO_LINGER{1,0} abortive close -> RST, no FIN swap"
cap_start r3 r1 6
echo_start --idle 1 --linger0
nt_ex h1 python3 "$root/py/slowclient.py" --mode idle --host "$SRV" --port "$PORT" \
    --seconds 4 >/tmp/nt-sock-row3.log 2>&1 &
CP=$!
sleep 3    # echod idle close with linger0
cap_stop_all
wait "$CP" 2>/dev/null || true
if tcpdump -nn -r /tmp/nt-sock-r3.pcap 'tcp' 2>/dev/null | grep -q '\[R\]'; then
    ok "row3: capture shows RST (linger0)"
else
    bad "row3: capture shows RST (linger0)"; tcpdump -nn -r /tmp/nt-sock-r3.pcap 2>/dev/null | sed 's/^/      /' | head -5
fi
if tcpdump -nn -r /tmp/nt-sock-r3.pcap 'tcp' 2>/dev/null | grep -q '\[F'; then
    bad "row3: no FIN segments expected with linger0"
else
    ok "row3: no FIN segments (abortive close)"
fi
echo_stop

echo; echo "== row 4: close with unread data on the server -> kernel sends RST"
echo "      predict: 100 KB in flight, echod holds the tail unread -> close() aborts with RST"
echo_start --idle 1
nt_ex h1 python3 - <<PY >/tmp/nt-sock-row4.log 2>&1 &
import socket, time
s = socket.create_connection(("$SRV", $PORT), timeout=5)
s.sendall(b"x" * 100000)   # more than echod's 64K staging: some stays unread
time.sleep(4)              # echod idle timer closes with unread data present
try:
    d = s.recv(4096)
    print("recv", len(d) if d else "EOF")
except OSError as e:
    print("oserr", getattr(e, "errno", None), e)
PY
CP=$!
sleep 3
cap_stop_all
wait "$CP" 2>/dev/null || true
if tcpdump -nn -r /tmp/nt-sock-r4.pcap 'tcp' 2>/dev/null | grep -q '\[R\]'; then
    ok "row4: capture shows RST (close with unread received data)"
else
    bad "row4: capture shows RST"; tcpdump -nn -r /tmp/nt-sock-r4.pcap 2>/dev/null | sed 's/^/      /' | head -5
fi
echo_stop

echo; echo "== row 5: accept-queue overflow: --max-conns 1 --no-accept --backlog 1"
echo "      predict: 2nd SYN completes the handshake in the kernel backlog, ss Recv-Q >= 1"
echo_start --max-conns 1 --no-accept --backlog 1 --idle 5
nt_ex rtr nstat -z >/dev/null 2>&1 || true
nt_ex h1 python3 "$root/py/loadgen.py" --mode tcp --host "$SRV" --port "$PORT" \
    --conns 2 --bytes 1024 --concurrent 2 >/tmp/nt-sock-row5.out 2>&1 &
CP=$!
sleep 0.6
q=$(nt_ex rtr ss -ltn 2>/dev/null | awk -v p=":$PORT " '$4 ~ p {print $2}' | head -1)
q=${q:-0}
if [[ $q -ge 1 ]]; then
    ok "row5: ss Recv-Q=$q (backlog occupied)"
else
    bad "row5: ss Recv-Q=$q (expect >=1)"; nt_ex rtr ss -ltn 2>/dev/null | sed 's/^/      /'
fi
nt_ex rtr nstat -z 2>/dev/null | grep -E "ListenOverflows|ListenDrops" | sed 's/^/      /' || true
wait "$CP" 2>/dev/null || true
echo_stop

echo; echo "== row 6: Nagle vs delayed ACK: two 1-byte writes, 50 ms apart"
echo "      predict: nagle may coalesce into 1 segment; --nodelay sends 2"
for mode in nagle nodelay; do
    extra=()
    [[ $mode == nodelay ]] && extra=(--nodelay)
    cap_start "n6-$mode" r1 8
    echo_start --idle 5 "${extra[@]}"
    nt_ex h1 python3 - <<PY >/dev/null 2>&1
import socket, time
s = socket.create_connection(("$SRV", $PORT), timeout=5)
s.sendall(b"a"); time.sleep(0.05); s.sendall(b"b")
time.sleep(0.5); s.close()
PY
    sleep 0.4
    cap_stop_all
    segs=$(tcpdump -nn -r "/tmp/nt-sock-n6-$mode.pcap" 'tcp[13] & 8 != 0' 2>/dev/null | wc -l)
    echo "      $mode: $segs data segment(s) for 2 tiny writes"
    if [[ $mode == nagle ]]; then
        [[ $segs -le 2 ]] && ok "row6: nagle sent <= 2 segments" || bad "row6: nagle segment count"
    else
        [[ $segs -ge 2 ]] && ok "row6: nodelay sent >= 2 segments" || bad "row6: nodelay segment count"
    fi
    echo_stop
done

echo; echo "== row 7: IPv6 echo on the lab fd00:1::/64 link"
echo_start -6 --bind "$SRV6" --idle 5
nt_ex h1 sh -c "printf 'v6ok' | env NT_LAB=1 $ncx -6 -N -w3 $SRV6 $PORT" \
    >/tmp/nt-sock-row7.out 2>&1
rc=$?
if [[ $rc -eq 0 && $(cat /tmp/nt-sock-row7.out) == v6ok ]]; then
    ok "row7: IPv6 echo returned"
else
    bad "row7: IPv6 echo returned (rc=$rc)"; cat /tmp/nt-sock-row7.out | sed 's/^/      /'
fi
echo_stop

echo; echo "== row 8: UDP ICMP port-unreachable surfaces as ncx exit 3"
rc=0
nt_ex h1 sh -c "printf 'u' | env NT_LAB=1 $ncx -u -w2 $SRV 19999" \
    >/tmp/nt-sock-row8.out 2>&1 || rc=$?
if [[ $rc -eq 3 ]]; then
    ok "row8: ncx -u exit 3 on ICMP port-unreachable"
else
    bad "row8: ncx -u exit 3 (rc=$rc)"; cat /tmp/nt-sock-row8.out | sed 's/^/      /'
fi

cleanup
echo; echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
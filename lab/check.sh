#!/usr/bin/env bash
# Smoke-test the running lab. Exits non-zero if any check fails.
# usage: sudo lab/check.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$here/lib.sh"
nt_require_root

topo=$(cat "$NT_STATE" 2>/dev/null || true)
[[ -n "$topo" ]] || { echo "lab is down (run: sudo lab/up.sh)"; exit 1; }

pass=0; fail=0; skip=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; fail=$((fail+1)); }
skp()  { echo "SKIP  $1"; skip=$((skip+1)); }
t()    { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

# ping_ttl <from> <dst> <expected-ttl>
ping_ttl() {
  local out
  out=$(nt_ex "$1" ping -c1 -W1 "$2" 2>&1) || return 1
  [[ $out == *"ttl=$3"* ]]
}

# cap_works <host> <iface> <pinger> <dst>: tcpdump sees an ICMP packet
cap_works() {
  local f pid rc
  f=$(mktemp)
  nt_ex "$1" timeout 5 tcpdump -ni "$2" -c1 -w "$f" icmp >/dev/null 2>&1 &
  pid=$!
  sleep 0.7
  nt_ex "$3" ping -c2 -W1 "$4" >/dev/null 2>&1
  wait "$pid" 2>/dev/null
  [[ -s $f ]]; rc=$?
  rm -f "$f"
  return "$rc"
}

offload_off() {
  command -v ethtool >/dev/null 2>&1 || return 2
  nt_ex "$1" ethtool -k "$2" 2>/dev/null | grep -q 'tx-checksumming: off'
}

case "$topo" in
  basic)
    t "h1 -> rtr (L2 neighbour)"            nt_ex h1 ping -c1 -W1 10.0.1.1
    t "h1 -> h2 across the router"           nt_ex h1 ping -c1 -W1 10.0.2.2
    t "TTL on routed reply is 63 (one hop)"  ping_ttl h1 10.0.2.2 63
    t "TTL to direct neighbour is 64"        ping_ttl h1 10.0.1.1 64
    t "router forwards IPv4"                 test "$(nt_ex rtr sysctl -n net.ipv4.ip_forward)" = 1
    t "tcpdump sees ICMP on rtr/r1"          cap_works rtr r1 h1 10.0.2.2
    cap_dst="eth0"; cap_host=h1
    ;;
  bridge3)
    t "h1 -> h2 (same L2 segment)"           nt_ex h1 ping -c1 -W1 10.0.0.2
    t "h1 -> h3 (same L2 segment)"           nt_ex h1 ping -c1 -W1 10.0.0.3
    t "TTL stays 64 inside one segment"      ping_ttl h1 10.0.0.3 64
    t "bridge learned h1's MAC"              bash -c "ip netns exec ${NT_PREFIX}sw bridge fdb show br br0 | grep -qi 02:00:00:00:00:01"
    t "tcpdump sees ICMP on h2/eth0"         cap_works h2 eth0 h1 10.0.0.2
    cap_dst="eth0"; cap_host=h1
    ;;
  *) echo "no checks defined for topology '$topo'"; exit 1 ;;
esac

if [[ "${NT_OFFLOAD:-0}" == 1 ]]; then
  skp "offloads disabled (NT_OFFLOAD=1)"
else
  offload_off "$cap_host" "$cap_dst"; rc=$?
  if [[ $rc -eq 0 ]]; then ok "tx checksum offload off on $cap_host/$cap_dst"
  elif [[ $rc -eq 2 ]]; then skp "ethtool not installed"
  else bad "tx checksum offload still on (captures will show bad checksums)"; fi
fi

smoke="$root/build/asan/bin/smoke"
if [[ -x $smoke ]]; then
  t "AF_PACKET raw socket opens inside $cap_host" nt_ex "$cap_host" "$smoke"
else
  skp "smoke binary not built (make BUILD=asan)"
fi

echo; echo "passed=$pass failed=$fail skipped=$skip"
[[ $fail -eq 0 ]]

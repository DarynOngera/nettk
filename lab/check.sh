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
t_skip2() { local d=$1; shift; "$@"; case $? in 0) ok "$d";; 2) skp "$d";; *) bad "$d";; esac; }

nt_tool() { local host=$1 bin=$2; shift 2; nt_ex "$host" env NT_LAB=1 "$bin" "$@"; }

hop_addrs() { awk 'NR>1 && $2!="*" {print $2}'; }

# Compare our traceroute's hop addresses against traceroute(8); 0=match, 2=skip.
trace_oracle_match() {
  local from=$1 target=$2 mode=${3:-udp} bin="$root/build/asan/bin/traceroute"
  [[ -x $bin ]] || return 2
  command -v traceroute >/dev/null 2>&1 || return 2
  local ourflag=() sysflag=(-U)
  [[ $mode == icmp ]] && { ourflag=(-I); sysflag=(-I); }
  local mine oracle
  mine=$(nt_tool "$from" "$bin" -n -W1000 -m5 "${ourflag[@]}" "$target" 2>/dev/null | hop_addrs)
  oracle=$(nt_tool "$from" traceroute -n -q1 -w1 -m5 "${sysflag[@]}" "$target" 2>/dev/null | hop_addrs)
  [[ -n $mine && "$mine" == "$oracle" ]]
}

# Compare the resolved MAC against arping(8); 0=match, 2=skip.
arp_oracle_match() {
  local from=$1 iface=$2 target=$3 bin="$root/build/asan/bin/arp"
  [[ -x $bin ]] || return 2
  command -v arping >/dev/null 2>&1 || return 2
  local mine oracle
  mine=$(nt_tool "$from" "$bin" -i "$iface" -c1 -W1000 "$target" 2>/dev/null \
         | awk '/Unicast reply/{print $5}' | tr -d '[]' | head -1)
  oracle=$(nt_tool "$from" arping -I "$iface" -c1 "$target" 2>/dev/null \
           | sed -nE 's/.*\[([0-9a-fA-F:]+)\].*/\1/p' | head -1)
  [[ -n $mine && "$mine" == "$oracle" ]]
}

# Compare an ARP scan against nmap -sn -PR; 0=match, 2=skip.
scan_oracle_match() {
  local from=$1 iface=$2 cidr=$3 self=$4 bin="$root/build/asan/bin/arp"
  [[ -x $bin ]] || return 2
  command -v nmap >/dev/null 2>&1 || return 2
  local mine oracle
  mine=$(nt_tool "$from" "$bin" scan -i "$iface" "$cidr" 2>/dev/null \
         | awk '/is-at/{print $1, $3}' | grep -v "^$self " | sort)
  oracle=$(nt_tool "$from" nmap -sn -PR -n "$cidr" 2>/dev/null \
           | awk '/Nmap scan report/{ip=$NF} /MAC Address/{print ip, tolower($3)}' \
           | grep -v "^$self " | sort)
  [[ -n $mine && "$mine" == "$oracle" ]]
}

# Compare the NDP-resolved MAC against the kernel's own neighbour entry; 2=skip.
ndp_oracle_match() {
  local from=$1 iface=$2 target=$3 bin="$root/build/asan/bin/ndp"
  [[ -x $bin ]] || return 2
  nt_ex "$from" ping -6 -c2 -W1 "$target" >/dev/null 2>&1 || true
  local mine oracle
  mine=$(nt_tool "$from" "$bin" -i "$iface" -c3 -W1000 "$target" 2>/dev/null | awk '/is-at/{print $3}')
  oracle=$(nt_ex "$from" ip -6 neigh show "$target" dev "$iface" 2>/dev/null \
           | awk '/lladdr/{for(i=1;i<=NF;i++) if($i=="lladdr") print tolower($(i+1))}' | head -1)
  [[ -n $mine && "$mine" == "$oracle" ]]
}

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
    # -c2: the first echo can race the router's NDP for fd00:2::2 on a cold cache.
    t "h1 -> h2 IPv6 across the router"      nt_ex h1 ping -6 -c2 -W1 fd00:2::2
    t_skip2 "traceroute UDP hop list matches oracle" trace_oracle_match h1 10.0.2.2
    t_skip2 "traceroute ICMP hop list matches oracle" trace_oracle_match h1 10.0.2.2 icmp
    t_skip2 "arp MAC matches arping"         arp_oracle_match h1 eth0 10.0.1.1
    t_skip2 "ndp MAC matches ip -6 neigh"    ndp_oracle_match h1 eth0 fd00:1::1
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
    t_skip2 "arp scan matches nmap -sn -PR"  scan_oracle_match h1 eth0 10.0.0.0/24 10.0.0.1
    cap_dst="eth0"; cap_host=h1
    ;;
  line4)
    t "h1 -> h2 across two routers"          nt_ex h1 ping -c1 -W1 10.0.2.2
    t "TTL on routed reply is 62 (two hops)" ping_ttl h1 10.0.2.2 62
    t "first router forwards IPv4"           test "$(nt_ex r1 sysctl -n net.ipv4.ip_forward)" = 1
    t "second router forwards IPv4"          test "$(nt_ex r2 sysctl -n net.ipv4.ip_forward)" = 1
    t_skip2 "traceroute UDP hop list matches oracle" trace_oracle_match h1 10.0.2.2
    t_skip2 "traceroute ICMP hop list matches oracle" trace_oracle_match h1 10.0.2.2 icmp
    t "tcpdump sees ICMP on r1/e1"           cap_works r1 e1 h1 10.0.2.2
    cap_dst="e1"; cap_host=r1
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

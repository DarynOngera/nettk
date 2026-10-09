#!/usr/bin/env bash
# Compare our traceroute hop list against traceroute(8) on a running lab topology.
#
# usage: sudo scripts/oracle-traceroute.sh [topo] [target] [udp|icmp]
#
# The oracle is `traceroute -n -U` (UDP) or `traceroute -n -I` (ICMP) inside h1,
# numeric output, one query. We compare the ordered list of responding hop
# addresses; timeout stars are ignored so a single dropped probe does not fail.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$root/lab/lib.sh"
nt_require_root

topo=${1:-$(cat "$NT_STATE" 2>/dev/null || true)}
[[ -n $topo ]] || { echo "lab is down (run: sudo lab/up.sh)"; exit 2; }

case "$topo" in
  basic|line4) from=h1; target=${2:-10.0.2.2} ;;
  *) echo "no traceroute oracle defined for topology '$topo'" >&2; exit 2 ;;
esac

mode=${3:-udp}
case "$mode" in
  udp)  ourflag=();     sysflag=(-U) ;;
  icmp) ourflag=(-I);   sysflag=(-I) ;;
  *) echo "mode must be udp or icmp" >&2; exit 2 ;;
esac

bin="$root/build/asan/bin/traceroute"
[[ -x $bin ]] || bin="$root/build/release/bin/traceroute"
[[ -x $bin ]] || { echo "no traceroute binary (run: make BUILD=asan all)" >&2; exit 2; }
command -v traceroute >/dev/null 2>&1 || { echo "traceroute(8) not installed"; exit 2; }

hops() { awk 'NR>1 && $2!="*" {print $2}'; }

mine=$(nt_ex "$from" env NT_LAB=1 "$bin" -n -W1000 -m5 "${ourflag[@]}" "$target" | hops)
oracle=$(nt_ex "$from" traceroute -n -q1 -w1 -m5 "${sysflag[@]}" "$target" | hops)

echo "topology: $topo   from $from   target $target   mode: $mode"
echo "mine:     $(echo "$mine" | paste -sd' ' -)"
echo "oracle:   $(echo "$oracle" | paste -sd' ' -)"
if [[ -n $mine && "$mine" == "$oracle" ]]; then
    echo "PASS hop list matches traceroute(8)"
else
    echo "FAIL hop list differs" >&2
    exit 1
fi

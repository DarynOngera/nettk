#!/usr/bin/env bash
# M9 lab validation for Phase 1.
#
# Runs a live AF_PACKET capture on the router's h1-facing port while generating
# ping / TCP / DNS traffic inside the nt-* lab, then checks the sniffer's live
# --tsv against tshark reading the pcap the sniffer itself wrote, and prints the
# CAP_NET_RAW-only capability of the capture process.
#
# Root only. Touches nothing outside nt-* namespaces.
#   sudo scripts/lab-validation.sh [N]     (N = packets to capture, default 40)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$root/lab/lib.sh"
nt_require_root
nt_need ip tshark || exit 1

N=${1:-40}
SNIFF=$root/build/asan/bin/sniff
[[ -x $SNIFF ]] || { echo "build first: make BUILD=asan all" >&2; exit 1; }

if [[ -z "$(nt_ns_list)" ]]; then
  echo "lab is down; run: sudo lab/up.sh basic" >&2
  exit 1
fi

evid=$root/docs/phase1-evidence
mkdir -p "$evid"
work=$(mktemp -d /tmp/nettk-labval.XXXXXX)
chmod 777 "$work"
cleanup() {
  [[ -n "${sniff_pid:-}" ]] && kill "$sniff_pid" 2>/dev/null || true
  [[ -n "${http_pid:-}" ]] && kill "$http_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "== starting live sniff on rtr/r1 (N=$N) -> $work/live.pcap"
ip netns exec "$(nt_ns rtr)" "$SNIFF" -i r1 --tsv -c "$N" -w "$work/live.pcap" \
  > "$work/live.tsv" 2> "$work/live.stderr" &
sniff_pid=$!
sleep 0.5

if [[ -r /proc/$sniff_pid/status ]]; then
  echo "== capabilities of sniff pid $sniff_pid (expect only cap_net_raw in CapEff):"
  grep -E '^(Cap(Inh|Prm|Eff|Bnd)|Uid|Gid):' "/proc/$sniff_pid/status" | sed 's/^/   /'
fi

echo "== generating traffic"
nt_ex h1 ip neigh flush all >/dev/null 2>&1 || true
nt_ex h1 ping -c 5 -i 0.2 10.0.2.2 >/dev/null 2>&1 || true

if command -v python3 >/dev/null 2>&1; then
  ip netns exec "$(nt_ns h2)" python3 -m http.server 8080 --bind 10.0.2.2 \
    >/dev/null 2>&1 &
  http_pid=$!
  sleep 0.5
  if command -v curl >/dev/null 2>&1; then
    nt_ex h1 curl -s -m 2 http://10.0.2.2:8080/ >/dev/null 2>&1 || true
  else
    nt_ex h1 bash -c 'exec 3<>/dev/tcp/10.0.2.2/8080; echo hi >&3' >/dev/null 2>&1 || true
  fi
fi

if command -v dig >/dev/null 2>&1; then
  nt_ex h1 dig +time=1 +tries=1 @10.0.2.2 example.com >/dev/null 2>&1 || true
fi
nt_ex h1 ping -c 3 -i 0.2 10.0.2.2 >/dev/null 2>&1 || true

echo "== waiting for sniff to reach N packets"
for _ in $(seq 1 40); do
  kill -0 "$sniff_pid" 2>/dev/null || break
  sleep 0.25
done
kill "$sniff_pid" 2>/dev/null || true
wait "$sniff_pid" 2>/dev/null || true
[[ -n "${http_pid:-}" ]] && kill "$http_pid" 2>/dev/null || true

cat "$work/live.stderr" | sed 's/^/   sniff: /'

if [[ ! -s "$work/live.pcap" ]]; then
  echo "FAIL: no packets captured" >&2
  exit 1
fi

echo "== tshark reading the sniffer's own pcap"
"$here/tshark-fields.sh" "$work/live.pcap" > "$work/live-tshark.tsv"

# Live Ethernet on veth does not fragment here, but normalize anyway so an odd
# frame cannot cause a spurious mismatch.
norm() { awk -F'\t' 'BEGIN{OFS="\t"} { if ($11=="True"||$12+0!=0) for(i=17;i<=25;i++) $i=""; print }' "$1"; }
norm "$work/live.tsv" > "$work/a.tsv"
norm "$work/live-tshark.tsv" > "$work/b.tsv"

packets=$(wc -l < "$work/a.tsv")
if diff -u "$work/a.tsv" "$work/b.tsv" > "$work/diff.txt"; then
  echo "PASS: live --tsv matches tshark on $packets packets"
  rc=0
else
  echo "DIFFERENCES (sniff vs tshark):"
  sed 's/^/   /' "$work/diff.txt"
  rc=1
fi

cp "$work/live.tsv" "$evid/live-sniff.tsv"
cp "$work/live-tshark.tsv" "$evid/live-tshark.tsv"
cp "$work/live.pcap" "$evid/live.pcap"
echo "== saved $evid/live-sniff.tsv, live-tshark.tsv, live.pcap"
exit $rc

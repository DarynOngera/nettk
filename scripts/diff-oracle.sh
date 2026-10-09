#!/usr/bin/env bash
# Compare our sniffer's --tsv output against the tshark oracle.
#
# usage: scripts/diff-oracle.sh <file.pcap> [sniff-binary]
#
# Divergence we knowingly normalize: for IPv4 fragments tshark only dissects the
# transport header on the last fragment; we dissect it on the first (frag_off==0).
# L4 columns (17..25) are blanked for any fragment row on both sides before diffing.
set -euo pipefail

[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 <file.pcap> [sniff-binary]" >&2; exit 2; }
pcap=$1
sniff=${2:-build/asan/bin/sniff}
[[ -x $sniff ]] || { echo "no sniffer at $sniff (run: make all)" >&2; exit 2; }
[[ -r $pcap ]] || { echo "cannot read $pcap" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$sniff" -r "$pcap" --tsv 2>"$tmp/sniff.err" > "$tmp/mine.tsv"
scripts/tshark-fields.sh "$pcap" > "$tmp/oracle.tsv" 2>/dev/null

normalize() {
    awk -F'\t' -v OFS='\t' '
        { if ($11 == "True" || ($12 + 0) != 0) { for (i = 17; i <= 25; i++) $i = "" } }
        { print }
    ' "$1"
}

normalize "$tmp/mine.tsv" > "$tmp/mine.norm"
normalize "$tmp/oracle.tsv" > "$tmp/oracle.norm"

mine_n=$(wc -l < "$tmp/mine.tsv")
oracle_n=$(wc -l < "$tmp/oracle.tsv")
if [[ $mine_n -ne $oracle_n ]]; then
    echo "FAIL $pcap: packet count $mine_n != oracle $oracle_n" >&2
    exit 1
fi

if diff -u "$tmp/oracle.norm" "$tmp/mine.norm"; then
    echo "PASS $pcap: $mine_n packets match tshark (L4 on fragments normalized)"
else
    echo "FAIL $pcap: see diff above" >&2
    exit 1
fi

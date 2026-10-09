#!/usr/bin/env bash
# Oracle output: one TSV row per packet from tshark. Diff your decoder against this.
# usage: scripts/tshark-fields.sh file.pcap
set -euo pipefail
[[ $# -eq 1 ]] || { echo "usage: $0 file.pcap" >&2; exit 2; }
tshark -r "$1" -T fields -E separator=$'\t' -E occurrence=f \
  -e frame.number -e frame.len \
  -e eth.src -e eth.dst -e eth.type -e vlan.id \
  -e ip.src -e ip.dst -e ip.ttl -e ip.proto -e ip.flags.mf -e ip.frag_offset \
  -e ipv6.src -e ipv6.dst -e ipv6.nxt -e ipv6.hlim \
  -e tcp.srcport -e tcp.dstport -e tcp.flags \
  -e udp.srcport -e udp.dstport \
  -e icmp.type -e icmp.code \
  -e icmpv6.type -e icmpv6.code

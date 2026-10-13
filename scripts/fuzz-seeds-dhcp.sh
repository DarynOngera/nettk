#!/usr/bin/env bash
# Extract one raw DHCP *payload* seed per record into a libFuzzer corpus dir.
# UDP/67 and UDP/68 records contribute the UDP payload (the DHCP message).
# usage: scripts/fuzz-seeds-dhcp.sh <out-dir> [pcap ...]
set -euo pipefail
out=${1:-fuzz/corpus-dhcp}
shift || true
here=$(cd "$(dirname "$0")/.." && pwd)
pcaps=("$@")
if [[ ${#pcaps[@]} -eq 0 ]]; then
    shopt -s nullglob
    for p in "$here"/fixtures/dhcp-*.pcap; do pcaps+=("$p"); done
    shopt -u nullglob
fi
[[ ${#pcaps[@]} -gt 0 ]] || { echo "no dhcp pcaps; run 'make fixtures' first" >&2; exit 1; }

mkdir -p "$out"
python3 - "$out" "${pcaps[@]}" <<'PY'
import os, sys
from scapy.all import rdpcap
from scapy.layers.inet import UDP
out, paths = sys.argv[1], sys.argv[2:]
n = 0
for path in paths:
    base = os.path.basename(path)[:-5] if path.endswith(".pcap") else os.path.basename(path)
    try:
        pkts = rdpcap(path)
    except Exception as e:
        print(f"skip {path}: {e}", file=sys.stderr)
        continue
    for i, p in enumerate(pkts):
        payload = None
        if UDP in p and (p[UDP].sport in (67, 68) or p[UDP].dport in (67, 68)):
            payload = bytes(p[UDP].payload)
        if not payload:
            continue
        with open(os.path.join(out, f"{base}_{i:03d}.bin"), "wb") as f:
            f.write(payload)
        n += 1
print(f"wrote {n} dhcp seeds to {out}")
PY

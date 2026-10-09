#!/usr/bin/env bash
# Extract one raw-packet seed per pcap record into a libFuzzer corpus directory.
# usage: scripts/fuzz-seeds.sh <out-dir> [pcap ...]
set -euo pipefail
out=${1:-fuzz/corpus}
shift || true
here=$(cd "$(dirname "$0")/.." && pwd)
pcaps=("$@")
if [[ ${#pcaps[@]} -eq 0 ]]; then
  shopt -s nullglob
  # arp-flood.pcap is 20k near-identical packets for the memory test, not fuzzing.
  for p in "$here"/fixtures/*.pcap; do
    [[ $p == *-flood.pcap ]] && continue
    pcaps+=("$p")
  done
  shopt -u nullglob
fi
[[ ${#pcaps[@]} -gt 0 ]] || { echo "no pcaps; run 'make fixtures' first" >&2; exit 1; }

mkdir -p "$out"
python3 - "$out" "${pcaps[@]}" <<'PY'
import os, sys
from scapy.all import rdpcap
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
        with open(os.path.join(out, f"{base}_{i:03d}.bin"), "wb") as f:
            f.write(bytes(p))
        n += 1
print(f"wrote {n} seeds to {out}")
PY

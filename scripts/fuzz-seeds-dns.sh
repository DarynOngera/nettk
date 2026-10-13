#!/usr/bin/env bash
# Extract one raw DNS *payload* seed per record into a libFuzzer corpus dir.
# UDP/53 records contribute the UDP payload; TCP/53 records contribute the
# message body with the RFC 7766 2-octet length prefix stripped.
# usage: scripts/fuzz-seeds-dns.sh <out-dir> [pcap ...]
set -euo pipefail
out=${1:-fuzz/corpus-dns}
shift || true
here=$(cd "$(dirname "$0")/.." && pwd)
pcaps=("$@")
if [[ ${#pcaps[@]} -eq 0 ]]; then
    shopt -s nullglob
    for p in "$here"/fixtures/dns-*.pcap; do pcaps+=("$p"); done
    shopt -u nullglob
fi
[[ ${#pcaps[@]} -gt 0 ]] || { echo "no dns pcaps; run 'make fixtures' first" >&2; exit 1; }

mkdir -p "$out"
python3 - "$out" "${pcaps[@]}" <<'PY'
import os, sys
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP
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
        if UDP in p and (p[UDP].sport == 53 or p[UDP].dport == 53):
            payload = bytes(p[UDP].payload)
        elif TCP in p and (p[TCP].sport == 53 or p[TCP].dport == 53):
            body = bytes(p[TCP].payload)
            if len(body) >= 2:
                payload = body[2:2 + ((body[0] << 8) | body[1])]
        if not payload:
            continue
        with open(os.path.join(out, f"{base}_{i:03d}.bin"), "wb") as f:
            f.write(payload)
        n += 1
print(f"wrote {n} dns seeds to {out}")
PY

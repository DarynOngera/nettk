#!/usr/bin/env bash
# Show addresses, routes, and neighbour tables for every lab namespace.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/lib.sh"
nt_require_root
list=$(nt_ns_list)
if [[ -z "$list" ]]; then echo "lab is down"; exit 0; fi
echo "topology: $(cat "$NT_STATE" 2>/dev/null || echo unknown)"
for ns in $list; do
  echo; echo "=== $ns ==="
  ip -n "$ns" -br link
  ip -n "$ns" -br addr
  ip -n "$ns" route
  ip -n "$ns" neigh
done

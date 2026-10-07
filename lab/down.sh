#!/usr/bin/env bash
# Tear down every lab namespace (veths disappear with them).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/lib.sh"
nt_require_root
for ns in $(nt_ns_list); do
  ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$ns"
  echo "removed $ns"
done
rm -f "$NT_STATE"

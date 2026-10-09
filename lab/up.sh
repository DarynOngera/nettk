#!/usr/bin/env bash
# Build a lab topology.  usage: sudo lab/up.sh [basic|line4|bridge3] [--force]
set -eEuo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/lib.sh"

topo=${1:-basic}
force=${2:-}
if [[ ! -f "$here/topo/$topo.sh" ]]; then
  echo "unknown topology '$topo'. available:" >&2
  ls "$here/topo" | sed 's/\.sh$//;s/^/  /' >&2
  exit 2
fi
nt_require_root
nt_need ip || exit 1

if [[ -n "$(nt_ns_list)" ]]; then
  if [[ $force == --force ]]; then
    "$here/down.sh"
  else
    echo "lab already up ($(cat "$NT_STATE" 2>/dev/null || echo unknown)); run lab/down.sh or pass --force" >&2
    exit 1
  fi
fi

source "$here/topo/$topo.sh"
trap '"$here/down.sh" >/dev/null 2>&1 || true; echo "setup failed; rolled back" >&2' ERR
topo_up
trap - ERR
echo "$topo" > "$NT_STATE"
echo "lab '$topo' is up."
topo_hint

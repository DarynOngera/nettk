#!/usr/bin/env bash
# Capture on a lab interface into captures/<host>-<if>-<timestamp>.pcap
# usage: sudo lab/cap.sh <host> <iface> [bpf filter...]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/lib.sh"
[[ $# -ge 2 ]] || { echo "usage: $0 <host> <iface> [bpf filter...]" >&2; exit 2; }
nt_require_root
nt_need tcpdump || exit 1
mkdir -p "$here/../captures"
f="$here/../captures/$1-$2-$(date +%Y%m%d-%H%M%S).pcap"
echo "capturing on $(nt_ns "$1")/$2 -> $f  (Ctrl-C to stop)"
cleanup() {
  if [[ -n "${SUDO_USER:-}" && -e $f ]]; then chown "$SUDO_USER" "$f"; fi
}
trap cleanup EXIT
nt_ex "$1" tcpdump -ni "$2" -U -Z root -w "$f" "${@:3}" || true

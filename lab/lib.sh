#!/usr/bin/env bash
# Shared helpers for the lab harness. Source this file; do not execute it.
#
# Environment knobs:
#   NT_PREFIX   namespace name prefix            (default: nt-)
#   NT_OFFLOAD  1 = keep NIC offloads on         (default: 0, offloads off)
#   NT_IPV6     0 = disable IPv6 in namespaces   (default: 1, enabled)
#   NT_STATE    file recording the active topo   (default: /run/nettk.topo)

NT_PREFIX="${NT_PREFIX:-nt-}"
NT_STATE="${NT_STATE:-/run/nettk.topo}"

nt_ns() { echo "${NT_PREFIX}$1"; }

nt_require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "error: needs root (try: sudo $0 ...)" >&2
    exit 1
  fi
}

# nt_need cmd...  -> non-zero if any command is missing
nt_need() {
  local c missing=0
  for c in "$@"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      echo "missing: $c" >&2
      missing=1
    fi
  done
  return "$missing"
}

# nt_ex <host> <cmd...>   run a command inside nt-<host>
nt_ex() {
  local ns
  ns=$(nt_ns "$1")
  shift
  ip netns exec "$ns" "$@"
}

# nt_ns_list -> names of lab namespaces (with prefix)
nt_ns_list() {
  ip netns list 2>/dev/null | awk '{print $1}' | grep "^${NT_PREFIX}" || true
}

# nt_ns_add <host>
nt_ns_add() {
  local ns
  ns=$(nt_ns "$1")
  ip netns add "$ns"
  ip -n "$ns" link set lo up
  if [[ "${NT_IPV6:-1}" == 0 ]]; then
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  fi
}

# nt_veth <host1> <if1> <host2> <if2>   create a veth pair across two namespaces
nt_veth() {
  ip link add "$2" netns "$(nt_ns "$1")" type veth peer name "$4" netns "$(nt_ns "$3")"
}

# nt_tune_if <host> <dev>
# Offloads make captures lie: outgoing checksums show up as "bad" and frames can
# exceed the MTU. Off by default so decoders see real bytes. NT_OFFLOAD=1 keeps
# defaults so you can study the artifact (see docs/phase0.md).
nt_tune_if() {
  if [[ "${NT_OFFLOAD:-0}" == 1 ]]; then
    return 0
  fi
  if command -v ethtool >/dev/null 2>&1; then
    nt_ex "$1" ethtool -K "$2" tx off rx off tso off gso off gro off lro off \
      >/dev/null 2>&1 || true
  fi
}

# nt_cfg_if <host> <dev> <cidr|-> <mac|->   set MAC/address, bring up, tune
nt_cfg_if() {
  local ns dev cidr mac
  ns=$(nt_ns "$1"); dev=$2; cidr=${3:--}; mac=${4:--}
  if [[ $mac != - ]]; then
    ip -n "$ns" link set dev "$dev" address "$mac"
  fi
  if [[ $cidr != - ]]; then
    ip -n "$ns" addr add "$cidr" dev "$dev"
  fi
  ip -n "$ns" link set dev "$dev" up
  nt_tune_if "$1" "$dev"
}

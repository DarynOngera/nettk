#!/usr/bin/env bash
# Apply a DHCP lease to a lab namespace interface.
#
# This is the one place in the DHCP phase that runs commands, so it is a
# script, not a C tool (docs/phase4-6-prompt.md rule 75). It never sources or
# evals the lease: every field is parsed with a strict allowlist and passed to
# `ip` as a separate argument, so option values can never reach a shell.
#
#   lab/apply-lease.sh <ns> --lease-file <file>       apply to nt-<ns>
#   lab/apply-lease.sh <ns> --check --lease-file <f>  validate, print, do not run
#   lab/apply-lease.sh <ns> --ip 10.0.6.100/24 --router 10.0.6.1 [--dns 10.0.6.1]
#
# Lease file (written by dhcpc --lease-file, or hand-made for testing):
#   ns=c1
#   ip=10.0.6.100/24
#   router=10.0.6.1
#   dns=10.0.6.1
#   server_id=10.0.6.1
#   lease=60
#
# The interface is `eth0` unless --dev says otherwise. DNS is NOT written to
# /etc/resolv.conf (we never touch host or namespace files); the nameserver
# line is printed, and optionally written to --resolv-out if given.
set -euo pipefail

die() { echo "apply-lease: error: $*" >&2; exit 1; }

ns=""
dev="eth0"
check=0
lease_file=""
ip=""
router=""
dns=""
server_id=""
lease=""
resolv_out=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev)       dev=${2:?--dev needs a value}; shift 2 ;;
    --check)     check=1; shift ;;
    --lease-file) lease_file=${2:?--lease-file needs a value}; shift 2 ;;
    --ip)        ip=${2:?--ip needs a value}; shift 2 ;;
    --router)    router=${2:?--router needs a value}; shift 2 ;;
    --dns)       dns=${2:?--dns needs a value}; shift 2 ;;
    --resolv-out) resolv_out=${2:?--resolv-out needs a value}; shift 2 ;;
    -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
    -*)          die "unknown option '$1'" ;;
    *)           [[ -z $ns ]] || die "unexpected argument '$1'"; ns=$1; shift ;;
  esac
done

[[ -n $ns ]] || die "usage: lab/apply-lease.sh <ns> --lease-file <file> [--check]"

# Namespace names are always ours; keep the prefix scoped (AGENTS.md rule 5).
[[ $ns =~ ^[A-Za-z0-9_]+$ ]] || die "bad namespace name '$ns'"
[[ $dev =~ ^[A-Za-z0-9_]+$ ]] || die "bad device name '$dev'"

valid_ip4() {  # dotted quad, 0-255 each
  local a=$1 o
  [[ $a =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

valid_cidr() { # A.B.C.D/len
  local a=$1
  [[ $a == */* ]] || return 1
  valid_ip4 "${a%/*}" || return 1
  local len=${a#*/}
  [[ $len =~ ^[0-9]{1,2}$ ]] && (( len >= 1 && len <= 32 ))
}

in_lab() { # inside 10.0.6.0/24 (the dhcp1 range)
  local a=$1
  [[ $a == 10.0.6.* ]] || return 1
  local last=${a##*.}
  [[ $last =~ ^[0-9]{1,3}$ ]] && (( last >= 1 && last <= 254 ))
}

# --- parse the lease file (strict key=value, no eval) -----------------------
if [[ -n $lease_file ]]; then
  [[ -r $lease_file ]] || die "cannot read lease file '$lease_file'"
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || $line == \#* ]] && continue
    [[ $line == *=* ]] || die "malformed lease line: '$line'"
    k=${line%%=*}
    v=${line#*=}
    # No control characters, backticks, $ or ; in a value.
    [[ $v =~ ^[A-Za-z0-9_./:=-]+$ ]] || die "rejected value for '$k': '$v'"
    case "$k" in
      ns)        [[ $ns == "$v" ]] || die "lease file ns '$v' does not match '$ns'" ;;
      ip)        ip=$v ;;
      router)    router=$v ;;
      dns)       dns=$v ;;
      server_id) server_id=$v ;;
      lease)     lease=$v ;;
      dev)       [[ $v == "$dev" ]] || die "lease file dev '$v' does not match '$dev'" ;;
      *)         die "unknown lease key '$k'" ;;
    esac
  done < "$lease_file"
fi

# --- validate --------------------------------------------------------------
[[ -n $ip ]] || die "no ip in lease"
valid_cidr "$ip" || die "bad cidr '$ip'"
valid_ip4 "${ip%/*}" && in_lab "${ip%/*}" || die "lease ip '$ip' is not in the lab range 10.0.6.0/24"

if [[ -n $router ]]; then
  valid_ip4 "$router" || die "bad router '$router'"
  in_lab "$router" || die "router '$router' is not in the lab range"
fi
if [[ -n $dns ]]; then
  valid_ip4 "$dns" || die "bad dns '$dns'"
  in_lab "$dns" || die "dns '$dns' is not in the lab range"
fi
if [[ -n $server_id ]]; then
  valid_ip4 "$server_id" || die "bad server_id '$server_id'"
  in_lab "$server_id" || die "server_id '$server_id' is not in the lab range"
fi
if [[ -n $lease ]]; then
  [[ $lease =~ ^[0-9]+$ ]] || die "bad lease time '$lease'"
fi

# --- apply -----------------------------------------------------------------
run() {
  if (( check )); then
    echo "+ ip netns exec nt-$ns $*"
  else
    ip netns exec "nt-$ns" "$@"
  fi
}

echo "lease: ns=nt-$ns dev=$dev ip=$ip router=${router:-none} dns=${dns:-none}" \
     "server_id=${server_id:-none} lease=${lease:-none}"

run ip link set "$dev" up
run ip addr flush dev "$dev"
run ip addr add "$ip" dev "$dev"
if [[ -n $router ]]; then
  run ip route replace default via "$router" dev "$dev"
fi

if [[ -n $dns ]]; then
  echo "nameserver $dns"
  if [[ -n $resolv_out ]]; then
    if (( check )); then
      echo "+ write '$resolv_out': nameserver $dns"
    else
      printf 'nameserver %s\n' "$dns" > "$resolv_out"
    fi
  fi
fi

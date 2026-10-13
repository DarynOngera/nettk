#!/usr/bin/env bash
# Gate: lab/apply-lease.sh must accept a good lease and refuse every hostile
# lease file. No root needed: --check validates and prints, never runs `ip`.
#
#   usage: scripts/apply-lease-check.sh [apply-lease.sh path]
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
apply=${1:-$here/lab/apply-lease.sh}
[[ -x $apply ]] || { echo "no apply-lease.sh at $apply" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

expect_ok() {  # name file
  local name=$1 file=$2
  if out=$("$apply" c1 --check --lease-file "$file" 2>&1); then
    grep -q 'ip addr add' <<<"$out" || { echo "FAIL $name: no addr command" >&2; fail=1; }
    echo "ok   $name"
  else
    echo "FAIL $name: expected success, got: $out" >&2
    fail=1
  fi
}

expect_fail() {  # name file
  local name=$1 file=$2
  if out=$("$apply" c1 --check --lease-file "$file" 2>&1); then
    echo "FAIL $name: expected refusal, got: $out" >&2
    fail=1
  else
    echo "ok   $name (refused)"
  fi
}

printf 'ns=c1\nip=10.0.6.100/24\nrouter=10.0.6.1\ndns=10.0.6.1\nserver_id=10.0.6.1\nlease=60\n' >"$tmp/good"
expect_ok "good lease" "$tmp/good"

mk() { printf '%s\n' "$2" >"$tmp/$1"; }

mk oor        'ns=c1
ip=8.8.8.8/24'
mk prefix     'ns=c1
ip=10.0.6.100/33'
mk router_dns 'ns=c1
ip=10.0.6.100/24
router=evil.example.com'
mk semicolon  'ns=c1
ip=10.0.6.100/24
router=10.0.6.1; id'
mk unknown    'ns=c1
ip=10.0.6.100/24
gateway=10.0.6.1'
mk nsmis      'ns=c2
ip=10.0.6.100/24'
mk backtick   'ns=c1
ip=10.0.6.100/24
dns=`id`'
mk dns0       'ns=c1
ip=10.0.6.100/24
dns=0.0.0.0'
mk leasebad   'ns=c1
ip=10.0.6.100/24
lease=forever'
mk noip       'ns=c1
router=10.0.6.1'
mk control    "$(printf 'ns=c1\nip=10.0.6.100/24\ndns=10.0.6.1\rmalicious')"

expect_fail "ip out of lab range"   "$tmp/oor"
expect_fail "prefix length 33"      "$tmp/prefix"
expect_fail "router not an IP"      "$tmp/router_dns"
expect_fail "shell metacharacter"   "$tmp/semicolon"
expect_fail "unknown key"           "$tmp/unknown"
expect_fail "ns mismatch"           "$tmp/nsmis"
expect_fail "backtick command"      "$tmp/backtick"
expect_fail "dns outside lab"       "$tmp/dns0"
expect_fail "lease not numeric"     "$tmp/leasebad"
expect_fail "missing ip"            "$tmp/noip"
expect_fail "control character"     "$tmp/control"

[[ $fail -eq 0 ]] || exit 1
echo "ok: apply-lease.sh accepted 1 good and refused 11 hostile leases"

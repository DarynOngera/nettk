#!/usr/bin/env bash
# Manage the dnslab DNS servers.
#   sudo lab/svc.sh dns up        start nsd on root/tld/auth + unbound on rec
#   sudo lab/svc.sh dns down      stop them (safe to re-run when already down)
#   sudo lab/svc.sh dns status    what is listening on :53 in each node
#   sudo lab/svc.sh dns up-py     fallback: py/dnsd.py serves all three zones
# Requires the dnslab topology: sudo lab/up.sh dnslab
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/lib.sh"

root=$(cd "$here/.." && pwd)
zones=$here/dns/zones
hints=$here/dns/root.hints
build=$root/build/lab-dns
py_server=$root/py/dnsd.py

have_nsd=0; have_unbound=0
command -v nsd >/dev/null 2>&1 && have_nsd=1
command -v unbound >/dev/null 2>&1 && have_unbound=1

die() { echo "error: $*" >&2; exit 1; }

require_dnslab() {
  [[ -f "$NT_STATE" && "$(cat "$NT_STATE")" == dnslab ]] || \
    die "topo dnslab is not up; run: sudo lab/up.sh dnslab"
}

# servers -> lines: <ns> <addr> <zone> <zonefile>
servers() {
  echo "root 10.0.5.1 . $zones/root.zone"
  echo "tld  10.0.5.2 test. $zones/test.zone"
  echo "auth 10.0.5.3 example.test. $zones/example.test.zone"
}

gen_nsd() {  # ns addr zone zonefile
  local ns=$1 addr=$2 zone=$3 zf=$4
  mkdir -p "$build"
  cat > "$build/nsd-$ns.conf" <<EOF
server:
    ip-address: $addr
    server-count: 1
    username: ""
    pidfile: "$build/nsd-$ns.pid"
    logfile: "$build/nsd-$ns.log"
zone:
    name: "$zone"
    zonefile: "$zf"
EOF
}

gen_unbound() {
  mkdir -p "$build"
  cat > "$build/unbound.conf" <<EOF
server:
    interface: 10.0.5.53
    port: 53
    access-control: 10.0.5.0/24 allow
    access-control: 127.0.0.0/8 allow
    do-daemonize: no
    username: ""
    chroot: ""
    directory: "$build"
    root-hints: "$hints"
    qname-minimisation: yes
    verbosity: 1
EOF
}

dns_generate() {
  local ns addr zone zf
  while read -r ns addr zone zf; do gen_nsd "$ns" "$addr" "$zone" "$zf"; done < <(servers)
  gen_unbound
}

dns_up() {
  require_dnslab
  [[ $have_nsd -eq 1 ]] || die "nsd is not installed; run: sudo apt-get install -y nsd   (or use: lab/svc.sh dns up-py)"
  dns_generate
  local ns addr zone zf
  while read -r ns addr zone zf; do
    nt_ex "$ns" nsd -d -c "$build/nsd-$ns.conf" >>"$build/nsd-$ns.out" 2>&1 &
  done < <(servers)
  if [[ $have_unbound -eq 1 ]]; then
    nt_ex rec unbound -d -c "$build/unbound.conf" >>"$build/unbound.out" 2>&1 &
  else
    echo "note: unbound not installed; rec has no recursion oracle (sudo apt-get install -y unbound)"
  fi
  sleep 1
  dns_status
}

dns_up_py() {
  require_dnslab
  mkdir -p "$build"
  local ns addr zone zf
  while read -r ns addr zone zf; do
    nt_ex "$ns" python3 "$py_server" --addr "$addr" --port 53 --zone "$zf" \
      >>"$build/py-$ns.out" 2>&1 &
  done < <(servers)
  echo "py/dnsd fallback serving root/tld/auth; unbound oracle NOT running"
  sleep 1
  dns_status
}

dns_down() {
  local ns
  for ns in root tld auth rec; do
    nt_ex "$ns" pkill -x nsd 2>/dev/null || true
    nt_ex "$ns" pkill -x unbound 2>/dev/null || true
    nt_ex "$ns" pkill -f 'py/dnsd.py' 2>/dev/null || true
  done
  echo "dnslab dns servers stopped"
}

dns_status() {
  local ns
  for ns in root tld auth rec; do
    echo "== $ns =="
    nt_ex "$ns" ss -lunp 2>/dev/null | grep ':53 ' || echo "   nothing listening on :53"
  done
}

case "${1:-}" in
  dns)
    case "${2:-}" in
      up)     dns_up ;;
      up-py)  dns_up_py ;;
      down)   dns_down ;;
      status) require_dnslab; dns_status ;;
      *) echo "usage: sudo lab/svc.sh dns up|up-py|down|status"; exit 2 ;;
    esac
    ;;
  *) echo "usage: sudo lab/svc.sh dns up|up-py|down|status"; exit 2 ;;
esac
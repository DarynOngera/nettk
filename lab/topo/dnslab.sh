#!/usr/bin/env bash
# Topology "dnslab": six nodes on one L2 segment (10.0.5.0/24) via a bridge.
#   c1   10.0.5.10  client (dnsq, sniff)
#   root 10.0.5.1   authoritative zone "."        (delegates test.)
#   tld  10.0.5.2   authoritative zone "test."    (delegates example.test. + corp.test.)
#   auth 10.0.5.3   authoritative zone "example.test."
#   rec  10.0.5.53  unbound recursion oracle
#   evil 10.0.5.66  spoof lab (M15)
# MACs 02:00:00:00:05:NN.
topo_up() {
  nt_ns_add sw
  for n in c1 root tld auth rec evil; do nt_ns_add "$n"; done
  nt_ex sw ip link add br0 type bridge
  nt_veth c1  eth0 sw sc1;   nt_cfg_if c1  eth0 10.0.5.10/24 02:00:00:00:05:0a
  nt_veth root eth0 sw sroot; nt_cfg_if root eth0 10.0.5.1/24  02:00:00:00:05:01
  nt_veth tld  eth0 sw stld;  nt_cfg_if tld  eth0 10.0.5.2/24  02:00:00:00:05:02
  nt_veth auth eth0 sw sauth; nt_cfg_if auth eth0 10.0.5.3/24  02:00:00:00:05:03
  nt_veth rec  eth0 sw srec;  nt_cfg_if rec  eth0 10.0.5.53/24 02:00:00:00:05:35
  nt_veth evil eth0 sw sevil; nt_cfg_if evil eth0 10.0.5.66/24 02:00:00:00:05:42
  for s in sc1 sroot stld sauth srec sevil; do
    nt_cfg_if sw "$s" - -
    nt_ex sw ip link set "$s" master br0
  done
  nt_ex sw ip link set br0 up
}
topo_hint() {
  cat <<'HINT'
  sudo lab/svc.sh dns up                  # nsd on root/tld/auth, unbound on rec
  sudo lab/svc.sh dns up-py               # fallback: py/dnsd.py on the three zones
  sudo lab/ex c1 dig +norecurse @10.0.5.1 www.example.test.   # referral from root
  sudo lab/ex c1 dig +norecurse @10.0.5.3 www.example.test.   # authoritative answer
  sudo lab/ex c1 dig @10.0.5.53 www.example.test.             # unbound recursion
  sudo lab/cap.sh rec eth0                  # see the whole walk from the resolver
HINT
}
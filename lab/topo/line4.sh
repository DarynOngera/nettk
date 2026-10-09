# Topology "line4": h1 -- r1 -- r2 -- h2 across three routed subnets.
#   h1 eth0 10.0.1.2/24 <-> r1 e1 10.0.1.1/24
#   r1 e2 10.0.9.1/30   <-> r2 e1 10.0.9.2/30
#   r2 e2 10.0.2.1/24   <-> h2 eth0 10.0.2.2/24
# MACs follow 02:00:00:00:<net>:<host> so they are easy to spot in hex dumps.
# Used for: traceroute (two-router path), TTL/hop-limit work, ICMP error quotes.
topo_up() {
  local n
  for n in h1 r1 r2 h2; do nt_ns_add "$n"; done
  nt_veth h1 eth0 r1 e1
  nt_veth r1 e2   r2 e1
  nt_veth r2 e2   h2 eth0
  nt_cfg_if h1 eth0 10.0.1.2/24 02:00:00:00:01:02
  nt_cfg_if r1 e1   10.0.1.1/24 02:00:00:00:01:01
  nt_cfg_if r1 e2   10.0.9.1/30 02:00:00:00:09:01
  nt_cfg_if r2 e1   10.0.9.2/30 02:00:00:00:09:02
  nt_cfg_if r2 e2   10.0.2.1/24 02:00:00:00:02:01
  nt_cfg_if h2 eth0 10.0.2.2/24 02:00:00:00:02:02
  nt_ex h1 ip route add default via 10.0.1.1
  nt_ex h2 ip route add default via 10.0.2.1
  nt_ex r1 ip route add 10.0.2.0/24 via 10.0.9.2
  nt_ex r2 ip route add 10.0.1.0/24 via 10.0.9.1
  nt_ex r1 sysctl -qw net.ipv4.ip_forward=1
  nt_ex r2 sysctl -qw net.ipv4.ip_forward=1
}
topo_hint() {
  cat <<'HINT'
  sudo lab/ex h1 ping -c2 10.0.2.2        # two-router path, TTL 62 on the reply
  sudo lab/ex h1 traceroute -n 10.0.2.2   # hops 10.0.1.1, 10.0.9.1, 10.0.9.2, 10.0.2.2
  sudo lab/cap.sh r1 e1 icmp              # capture on the first hop
  sudo lab/status.sh                       # addresses, routes, neighbours
HINT
}

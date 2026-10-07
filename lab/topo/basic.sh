# Topology "basic": h1 -- rtr -- h2 across two routed /24 networks.
#   h1 eth0 10.0.1.2/24 <-> rtr r1 10.0.1.1/24 | rtr r2 10.0.2.1/24 <-> h2 eth0 10.0.2.2/24
# MACs follow 02:00:00:00:<net>:<host> so they are easy to spot in hex dumps.
# Used for: sniffer, ping, traceroute, TCP/UDP, DNS, scanner, router work.
topo_up() {
  local n
  for n in h1 rtr h2; do nt_ns_add "$n"; done
  nt_veth h1 eth0 rtr r1
  nt_veth h2 eth0 rtr r2
  nt_cfg_if h1  eth0 10.0.1.2/24 02:00:00:00:01:02
  nt_cfg_if rtr r1   10.0.1.1/24 02:00:00:00:01:01
  nt_cfg_if rtr r2   10.0.2.1/24 02:00:00:00:02:01
  nt_cfg_if h2  eth0 10.0.2.2/24 02:00:00:00:02:02
  nt_ex h1 ip route add default via 10.0.1.1
  nt_ex h2 ip route add default via 10.0.2.1
  nt_ex rtr sysctl -qw net.ipv4.ip_forward=1
}
topo_hint() {
  cat <<'HINT'
  sudo lab/ex h1 ping -c2 10.0.2.2        # routed path, TTL 63 on the reply
  sudo lab/cap.sh rtr r1 icmp              # capture on the router's h1-facing port
  sudo lab/status.sh                       # addresses, routes, neighbours
HINT
}

#!/usr/bin/env bash
# Topology "dhcp1": three nodes on one L2 segment (10.0.6.0/24) via a bridge.
#   c1     10.0.6.10?  client with NO IPv4 address (starts as 0.0.0.0)
#   dhcpd  10.0.6.1    dnsmasq DHCP server  (pool 10.0.6.100-150, short lease)
#   rogue  10.0.6.66   second dnsmasq, started on demand (different router/DNS)
# MACs 02:00:00:00:06:NN. c1 keeps its address in the config so the interface is
# up with a link-local-free, address-less state; lab/svc.sh dhcp starve swaps in
# a 10-address pool. See docs/phase6.md.
topo_up() {
  nt_ns_add sw
  for n in c1 dhcpd rogue; do nt_ns_add "$n"; done
  nt_ex sw ip link add br0 type bridge
  # c1 has no IPv4 address: the whole point is to get one over DHCP.
  nt_veth c1    eth0 sw sc1;   nt_cfg_if c1    eth0 -           02:00:00:00:06:0a
  nt_veth dhcpd eth0 sw sdhcp; nt_cfg_if dhcpd eth0 10.0.6.1/24  02:00:00:00:06:01
  nt_veth rogue eth0 sw srog;  nt_cfg_if rogue eth0 10.0.6.66/24 02:00:00:00:06:42
  for s in sc1 sdhcp srog; do
    nt_cfg_if sw "$s" - -
    nt_ex sw ip link set "$s" master br0
  done
  nt_ex sw ip link set br0 up
  # Do not let the kernel autoconfigure an IPv6 address on c1 (it would look
  # like a configured client); IPv6 is out of scope for this phase.
  nt_ex c1 sysctl -qw net.ipv6.conf.eth0.disable_ipv6=1 2>/dev/null || true
}
topo_hint() {
  cat <<'HINT'
dhcp1 topo: c1 (no address) + dhcpd 10.0.6.1 + rogue 10.0.6.66, one bridge.
  sudo lab/svc.sh dhcp up      start dnsmasq on dhcpd
  sudo lab/svc.sh dhcp status  what is listening on :67
  sudo lab/ex c1 ip -br addr    c1 still has no IPv4 address
  NT_LAB=1 build/asan/bin/dhcpc -i eth0 --apply
HINT
}

# Topology "bridge3": three hosts on one L2 segment (10.0.0.0/24) via a bridge.
#   h1 10.0.0.1, h2 10.0.0.2, h3 10.0.0.3; MACs 02:00:00:00:00:0N.
# Used for: ARP resolve/scan/spoof, rogue DHCP, observing broadcast domains.
topo_up() {
  local i
  nt_ns_add sw
  for i in 1 2 3; do nt_ns_add "h$i"; done
  nt_ex sw ip link add br0 type bridge
  for i in 1 2 3; do
    nt_veth "h$i" eth0 sw "s$i"
    nt_cfg_if "h$i" eth0 "10.0.0.$i/24" "02:00:00:00:00:0$i"
    nt_cfg_if sw "s$i" - -
    nt_ex sw ip link set "s$i" master br0
  done
  nt_ex sw ip link set br0 up
}
topo_hint() {
  cat <<'HINT'
  sudo lab/ex h1 ping -c1 10.0.0.2
  sudo lab/cap.sh h3 eth0                  # h3 sees ARP broadcasts, not h1<->h2 unicast
  sudo lab/ex sw bridge fdb show br br0    # which MAC was learned on which port
HINT
}

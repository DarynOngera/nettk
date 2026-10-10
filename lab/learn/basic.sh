# Basic topology tour: h1 -- rtr -- h2, IPv4 + IPv6, one routed hop.
# shellcheck shell=bash
# This file defines lesson_main(); run it via lab/wizard.sh basic.

TOPIC="basic: one router, both IP versions, TTL, traceroute, break it"

lesson_main() {
  lesson_start basic "$TOPIC"

  # ---------------------------------------------------------------- 1
  step "Read the fabric: what did up.sh actually build?"
  why <<'EOF'
  Three namespaces sit in front of you: h1, rtr, h2. Two veth pairs make two L2 links
  (10.0.1.0/24 and 10.0.2.0/24); the only thing joining them is the router's routing
  table and ip_forward. status.sh turns every namespace inside out so you can read
  the exact state each kernel stack is in.
EOF
  cmd "sudo lab/status.sh"
  run rtr ip -br addr
  run rtr ip route
  expect "10.0.1.1" "- rtr owns one address on each side: it is the boundary"
  note <<'EOF'
  The key rows: rtr has 10.0.1.1/24 on r1 AND 10.0.2.1/24 on r2. h1 has a *default* route
  pointing at 10.0.1.1; h2 points at 10.0.2.1. No host route exists to the far subnet --
  only the routers glue the two hops together.
EOF

  # ---------------------------------------------------------------- 2
  step "L2 resolution: what happens on the wire before the first ping"
  why <<'EOF'
  To send a packet to 10.0.1.1, h1 first needs its MAC. The neighbour layer (ARP) asks
  "who-has 10.0.1.1" as an Ethernet *broadcast*; rtr answers *unicast*; h1 stores the pair
  in its neighbour cache (REACHABLE). A cold cache is why the first ping can feel like one
  round-trip slower.
EOF
  cmd "sudo lab/ex h1 ip neigh flush all"
  run h1 ip neigh flush all
  cap h1 eth0 4 h1 ping -c1 -W1 10.0.1.1
  expect "eth.type   0x0806" "ARP appears on the wire as ethertype 0x0806 (below IP)" "no ARP frame captured"
  expect "ff:ff:ff:ff:ff:ff" "the request went to the Ethernet broadcast address" "no broadcast request captured"
  run h1 ip neigh show 10.0.1.1 dev eth0
  expect "REACHABLE" "the neighbour entry is REACHABLE: freshly verified by an exchange" "neighbour entry was not REACHABLE"
  note <<'EOF'
  Bytes 0-11 are the two MACs, bytes 12-13 are 0x0806. The reply is unicast to 02:00:00:00:01:02
  and its opcode (last bytes of the ARP payload) is 0x0002 = reply. Both directions differ:
  who-has is broadcast, the answer is point-to-point. That split is the broadcast domain.
EOF

  # ---------------------------------------------------------------- 3
  step "The router path: one hop, one TTL decrement"
  why <<'EOF'
  h1's packet for 10.0.2.2 leaves r1 with TTL 64. rtr decrements it to 63 and forwards it
  out r2. h2's reply is stamped 64 and rtr decrements it to 63 on the way back -- so h1
  reads ttl=63. One routed hop always costs exactly one TTL, no matter how far the physical
  wire is: TTL counts devices, not distance.
EOF
  predict <<'EOF'
  h1 pings h2 across rtr. What TTL will h1 read on the ICMP echo reply?
  a) 64  b) 63  c) 62
  answer b
  because h2 replies with TTL 64 and rtr decrements once on the return path. You infer the
  hop count by looking at the TTL, you never see the "real" initial value directly.
EOF
  cmd "sudo lab/ex h1 ping -c2 10.0.2.2"
  t_run h1 ping -c1 -W1 10.0.2.2
  expect "ttl=63" "reply arrived after exactly one decrement -- your forward path is 1 hop" "no ttl=63 reply (ping failed?)"
  cap rtr r1 6 h1 ping -c2 -W1 10.0.2.2
  expect "ip.ttl" "on rtr's h1-facing port you can read the field that gets decremented"
  note <<'EOF'
  On the rtr/r1 capture both directions are visible: the request passes with ttl=64 and the
  reply returns with ttl=63. That is the decrement happening *inside* rtr -- between r1 and
  r2. Now do the same ping and capture on h1's own eth0: ttl on the way out is 64, on the
  way in 63. Same field, two faces.
EOF

  # ---------------------------------------------------------------- 4
  step "The IPv6 path: NDP replaces ARP"
  why <<'EOF'
  IPv6 has no ARP frame. Instead, a Neighbor Solicitation (ICMPv6 type 135) is sent to a
  solicited-node multicast address and the router answers a Neighbor Advertisement (type
  136). The resolution still costs the first packet, but the protocol is ICMPv6 -- you will
  never see 0x0806 on the v6 path.
EOF
  cap h1 eth0 6 h1 ping -6 -c1 -W1 fd00:2::2
  expect "icmpv6" "the neighbour exchange is ICMPv6; there is no ARP on the v6 path" "no ICMPv6 frames captured"
  cmd "sudo lab/ex h1 ndp -i eth0 -c1 fd00:1::1"
  t_run h1 ndp -i eth0 -c1 -W1000 fd00:1::1
  expect "is-at" "ndp resolved rtr's link-layer address from a Neighbor Advertisement"
  run h1 ip -6 neigh show fd00:1::1 dev eth0
  expect "fd00:1::1" "the kernel cache now holds the rtr entry resolved by ND"
  predict <<'EOF'
  When h1 pings fd00:2::2 for the very first time, what is sent BEFORE the echo request?
  a) an ARP request  b) an ICMPv6 Neighbor Solicitation  c) a DHCPv6 exchange  d) nothing extra
  answer b
  because IPv6 replaced ARP with NDP (RFC 4861): the first packet's neighbour lookup is an
  ICMPv6 NS/NA pair, not an ARP frame.
EOF

  # ---------------------------------------------------------------- 5
  step "traceroute: TTL-exceeded per hop, port-unreachable at the end"
  why <<'EOF'
  traceroute sends UDP probes with TTL 1,2,3,... A router that must drop a probe (TTL hit 0)
  answers ICMP type 11 (time exceeded) and embeds the offending probe's first bytes. At the
  terminal host the UDP probe lands on an unused port, so h2 answers type 3 code 3 (port
  unreachable) -- that is the "we arrived" signal. Every hop name is learned from an ICMP
  error, never from the probe itself.
EOF
  cmd "sudo lab/ex h1 traceroute -n -W1000 -m5 10.0.2.2"
  t_run h1 traceroute -n -W1000 -m5 10.0.2.2
  expect "10.0.1.1" "hop 1 is rtr (its TTL-exceeded error is the first thing heard)"
  expect "10.0.2.2" "hop 2 is h2 (its port-unreachable finishes the walk)"
  cmd "system traceroute, the oracle:"
  run h1 traceroute -n -q1 -w1 -m5 10.0.2.2
  note <<'EOF'
  Your hop list and the system traceroute's must agree on every address. If not, do not
  guess: capture on rtr/r1 while both run and read which ICMP types arrive for which
  source -- the difference is in the frame, not in the printing.
EOF

  # ---------------------------------------------------------------- 6
  step "traceroute -I: the same geometry with ICMP probes"
  why <<'EOF'
  -I swaps UDP probes for ICMP echo requests. Successful arrival is an echo reply (type 0)
  instead of port-unreachable; the routers still answer TTL exceeded on the way out. Same
  hop list, different probe protocol on the wire -- an easy thing to confuse when reading
  a capture.
EOF
  cmd "sudo lab/ex h1 traceroute -n -I -W1000 -m5 10.0.2.2"
  t_run h1 traceroute -n -I -W1000 -m5 10.0.2.2
  expect "10.0.1.1" "rtr still answers TTL-exceeded for the ICMP probe"
  expect "10.0.2.2" "hop 2 answered the echo probe"
  note <<'EOF'
  With -I the middle of the trace has *three* ICMP types on the wire: type 11 from rtr,
  and the echo request/reply pair between h1 and h2. Reading the capture by type is the
  muscle to build.
EOF

  # ---------------------------------------------------------------- 7
  step "Break it: forwarding off makes the router a host"
  why <<'EOF'
  rtr is a router because of a sysctl (ip_forward=1), not because of any wire. Flip it to 0
  and rtr stops being willing to forward packets it is not addressed to. The observable
  result: the hop list never gets past rtr -- and what happens to the probes after rtr
  (explicit ICMP error vs a silent drop) tells you how the kernel treats "not for me".
EOF
  predict <<'EOF'
  Set rtr ip_forward=0, then run traceroute h1 -> 10.0.2.2. The hop list will:
  a) show every hop normally  b) stop after rtr  c) fail to resolve rtr itself
  answer b
  because rtr no longer forwards: the only hop that still answers is rtr itself (TTL
  exceeded on arrival). Nothing after rtr is on the path anymore.
EOF
  cmd "sudo lab/ex rtr sysctl -w net.ipv4.ip_forward=0"
  run rtr sysctl -w net.ipv4.ip_forward=0
  cmd "sudo lab/ex h1 traceroute -n -W1000 -m5 10.0.2.2"
  t_run h1 traceroute -n -W1000 -m5 10.0.2.2
  expect_absent "10.0.2.2" "rtr stopped forwarding: no h2 hop -- the break took effect" "h2 is still in the list; forwarding did not actually turn off"
  note <<'EOF'
  After rtr the probes vanish. Whether rtr answers with an ICMP error or drops silently is
  the lesson: many routers answer explicitly, a plain host whose forwarding is off defaults
  to dropping. Forwarding is policy, not plumbing.
EOF

  # ---------------------------------------------------------------- 8
  step "Break it: PMTU -- finding where the network says no"
  why <<'EOF'
  Shrink rtr/r2's MTU to 1400. A 1400-byte DF probe can *arrive* at rtr through r1 (MTU 1500)
  but cannot leave through r2. The device that cannot forward is the one that must say so:
  it answers ICMP type 3 code 4 (fragmentation needed) with the next-hop MTU inside the
  payload. Our traceroute -M do sets DF and prints it as !F mtu=...
EOF
  predict <<'EOF'
  After setting rtr/r2 mtu 1400, `traceroute -M do -s 1400 10.0.2.2` gets !F mtu=1400 from:
  a) h2  b) rtr  c) nobody; it succeeds  d) h1 itself
  answer b
  because rtr's egress (r2) cannot carry the oversized DF frame, and the device that cannot
  forward is the one that must reply with the reason.
EOF
  cmd "sudo lab/ex rtr ip link set r2 mtu 1400"
  run rtr ip link set r2 mtu 1400
  cmd "sudo lab/ex h1 traceroute -n -M do -s 1400 -W1000 -m5 10.0.2.2"
  t_run h1 traceroute -n -M do -s 1400 -W1000 -m5 10.0.2.2
  expect "!F" "the DF probe came back as fragmentation-needed" "no !F returned (payload under the new MTU?)"
  note <<'EOF'
  "!F mtu=1400" names the bottleneck on the h1 side of the break. Lower the probe size until
  it passes and you have the usable path MTU -- that is exactly what host-path MTU discovery
  does on your behalf, silently.
EOF

  # ---------------------------------------------------------------- 9
  step "Restore, then let the batch checks grade everything"
  why <<'EOF'
  The --force rebuild gives you a pristine fabric again. Batch checks (lab/check.sh) are the
  same experiments without the narration -- a fast, repeatable "did I break anything" gate
  after every future lab session.
EOF
  cmd "sudo lab/up.sh basic --force"
  cmd "sudo lab/check.sh"
  note <<'EOF'
  check.sh runs the 13 smoke checks for basic and prints passed/failed/skipped. The
  skipped lines are oracle comparisons (traceroute/arping/nmap) that drift when binaries
  change; every PASS is one of the behaviours you just saw narrated. Compare the numbers
  now and after your next break.
EOF

  report
}
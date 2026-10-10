# Line4 topology tour: h1 -- r1 -- r2 -- h2, two routed hops, TTL + ICMP errors.
# shellcheck shell=bash
# This file defines lesson_main(); run it via lab/wizard.sh line4.

TOPIC="line4: two routers, TTL 62, ICMP error quotes, PMTU"

lesson_main() {
  lesson_start line4 "$TOPIC"

  # ---------------------------------------------------------------- 1
  step "Read the fabric: the /30 nobody talks to"
  why <<'EOF'
  Four namespaces, three subnets. h1 (10.0.1.0/24) and h2 (10.0.2.0/24) never meet; the
  middle link is a point-to-point /30 (10.0.9.0/30) used only between r1 and r2. Traceroute
  will show you addresses from that middle link -- the first time in this lab you see a
  network that carries no hosts, only forwarding.
EOF
  cmd "sudo lab/status.sh"
  run r1 ip route
  expect "10.0.9.2" "r1 routes the far subnet through r2's /30 address"
  note <<'EOF'
  r1's forwarding table is the difference from `basic`: a *specific* route to 10.0.2.0/24
  via 10.0.9.2. If that route vanished, r1 would fall back to its local subnet and the
  far side would simply not exist from here.
EOF

  # ---------------------------------------------------------------- 2
  step "Two routers cost two TTL decrements"
  why <<'EOF'
  h1's ping to 10.0.2.2 crosses r1 and r2. Each router decrements TTL once, so h1 reads
  ttl=62 on the reply (64 - 2). The counter is per *device*, which is why a 10 000 km link
  can still be "one hop".
EOF
  predict <<'EOF'
  h1 pings h2 across r1 and r2. What TTL does h1 read on the echo reply?
  a) 64  b) 63  c) 62  d) 61
  answer c
  because the reply is stamped 64 at h2 and each of the two routers decrements once on the
  way back: 64 - (r2) - (r1) = 62. Hop count equals the TTL shortfall.
EOF
  cmd "sudo lab/ex h1 ping -c2 10.0.2.2"
  t_run h1 ping -c1 -W1 10.0.2.2
  expect "ttl=62" "reply arrived after exactly two decrements" "no ttl=62 reply"
  cap r1 e1 6 h1 ping -c2 -W1 10.0.2.2
  expect "ip.ttl" "on r1's h1-facing port both directions are visible -- read the two TTL values"
  note <<'EOF'
  On r1/e1 the request passes with ttl=64 and the reply returns with 62 (r2 did its
  decrement before r1's egress sniff point). Same notebook trick as `basic`, except the
  arithmetic is now 64 - 2. Compare with a capture on r2/e2 to see each router's share.
EOF

  # ---------------------------------------------------------------- 3
  step "traceroute across two routers: where the mid-hops come from"
  why <<'EOF'
  Every probe is a UDP packet with an increasing TTL. The first device that cannot forward
  it (TTL hit 0) returns ICMP type 11, sourced from the interface on which it *received*
  the probe. That rule decides which address each hop shows -- and Linux is specific about
  it: the error is emitted from the inbound interface, so an intermediate router usually
  shows its west-facing address, not its east-facing one.
EOF
  cmd "sudo lab/ex h1 traceroute -n -W1000 -m6 10.0.2.2"
  t_run h1 traceroute -n -W1000 -m6 10.0.2.2
  expect "10.0.1.1" "hop 1 is r1's west-facing address (10.0.1.1)"
  expect "10.0.2.2" "the walk ends at h2"
  run h1 traceroute -n -q1 -w1 -m6 10.0.2.2
  local mid
  mid=$(printf '%s\n' "$LAST_OUT" | grep -oE '10\.0\.9\.[12]' | sort -u | tr '\n' ' ')
  say "  [observed] router-to-router addresses that appeared: ${mid:-<none>}"
  echo "  [observed] mid hops: ${mid:-none}" >> "$LEARN_LOG"
  note <<'EOF'
  The middle of the list names the 10.0.9.0/30. Which exact address you see is your kernel's
  policy for TTL-exceeded sourcing (inbound vs egress interface). Write down what appeared
  and keep that as your answer for "what address will a TTL error come from on THIS lab".
  Our trace and the system traceroute must agree on the whole list -- that agreement is the
  oracle.
EOF

  # ---------------------------------------------------------------- 4
  step "traceroute -I: probe protocol changes, geometry does not"
  why <<'EOF'
  With -I the probes are ICMP echoes and "we arrived" is an echo reply (type 0) rather than
  port-unreachable. The routers still answer TTL-exceeded on the way out. The hop list must
  not change -- only the frame types in a capture do.
EOF
  cmd "sudo lab/ex h1 traceroute -n -I -W1000 -m6 10.0.2.2"
  t_run h1 traceroute -n -I -W1000 -m6 10.0.2.2
  expect "10.0.1.1" "r1 still emits the TTL-exceeded for the echo probe"
  expect "10.0.2.2" "h2 answered the echo probe"
  note <<'EOF'
  Same addresses as step 3. If they differ, the probe type itself leaks into the answer --
  a fingerprint to keep in mind when you later read pcap files.
EOF

  # ---------------------------------------------------------------- 5
  step "Reading an ICMP error: the quoted probe inside the reply"
  why <<'EOF'
  RFC 792 says a time-exceeded error must carry at least 28 bytes of the offending datagram
  back (its IP header + the first 8 bytes). A TTL=1 probe dies at r1; r1's ICMP error quotes
  the probe, so one capture shows both the probe *and* its own quote. Byte 42 of the frame
  is where the quoted IP header begins (14 eth + 8 ICMP + 20 quoted IP).
EOF
  cap r1 e1 3 h1 traceroute -q1 -m1 10.0.2.2
  expect "ip.ttl" "at least one IPv4 frame was decoded -- the probe and/or its error"
  note <<'EOF'
  In the hex, find the frame whose @ip.src@ is 10.0.1.1 and type is "time exceeded" — its
  payload re-prints the probe's IP header. This quoted-header trick is how traceroute learns
  the *sizes* (PMTU) and the *routes* (strict) of paths it never completes. Solve it once on
  this capture and you will never unsee it in tcpdump output.
EOF

  # ---------------------------------------------------------------- 6
  step "Break it: forwarding off on r1 makes the far side vanish"
  why <<'EOF'
  Turn r1 into a host (ip_forward=0). r1 still *sees* the probe for 10.0.2.2, but it no
  longer agrees to carry it toward r2. The observable fact: the hop list ends at r1 and
  never crosses the /30.
EOF
  predict <<'EOF'
  With r1 ip_forward=0, traceroute h1 -> 10.0.2.2 ends:
  a) at h2  b) after r1, never reaching the /30  c) at r1 but still showing 10.0.9.x
  answer b
  because r1 will not forward, so nothing it forwards can generate an error from the middle
  link; the /30 addresses never get a TTL-exceeded reason to appear.
EOF
  cmd "sudo lab/ex r1 sysctl -w net.ipv4.ip_forward=0"
  run r1 sysctl -w net.ipv4.ip_forward=0
  cmd "sudo lab/ex h1 traceroute -n -W1000 -m6 10.0.2.2"
  t_run h1 traceroute -n -W1000 -m6 10.0.2.2
  expect_absent "10.0.9" "the /30 never appears -- r1 stopped forwarding the probes" "a 10.0.9.x address appeared; forwarding is still on"
  predict <<'EOF'
  After r1 stops forwarding, the probes that pass r1 are:
  a) forwarded anyway  b) dropped, and r1 may answer or stay silent  c) returned to h1 intact
  answer b
  because forwarding is off, so "not for me" is the verdict; whether Linux says so out loud
  (an ICMP destination-unreachable) or stays silent is the kernel behaviour you just watched.
EOF

  # ---------------------------------------------------------------- 7
  step "Restore and batch-grade the two-router path"
  why <<'EOF'
  --force gives you fresh routers again. scenarios-traceroute is the narrated-less version
  of this tour: it verifies the !N/!X codes reachable by ordinary routing and the !F from
  the DF+MTU probe, using an nft rule inside the lab to force the answers.
EOF
  cmd "sudo lab/up.sh line4 --force"
  cmd "sudo lab/scenarios-traceroute.sh"
  note <<'EOF'
  Every PASS in the scenario is a behaviour this tour walked you through by hand. The !F
  there uses the same ICMP type 3 code 4 you would trigger with `-M do -s 1400` manually --
  one mechanism, two ways to call it.
EOF

  report
}
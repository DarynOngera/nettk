# Bridge3 topology tour: three hosts, one broadcast domain.
# shellcheck shell=bash
# ARP resolution, scan, hostile replies, broadcast vs unicast, poison + arpmon.
# This file defines lesson_main(); run it via lab/wizard.sh bridge3.

TOPIC="bridge3: one L2 segment, ARP attacks and the defences"

lesson_main() {
  lesson_start bridge3 "$TOPIC"

  TARGET=10.0.0.99

  # ---------------------------------------------------------------- 1
  step "Read the fabric: a bridge, not a router"
  why <<'EOF'
  Three hosts hang off one software bridge: h1 10.0.0.1, h2 10.0.0.2, h3 10.0.0.3. There
  is no routing here, only forwarding decisions by MAC. Every host can reach every other
  host with a single L2 hop -- and any host can *observe* the broadcast frames.
EOF
  run sw ip -br link
  run sw bridge fdb show br br0
  note <<'EOF'
  The bridge learns: the first frame a host sends teaches the bridge which port that MAC
  is behind. Until then, frames to an unknown MAC are flooded to every port (like a hub).
  That learning table is the whole difference between a hub and a switch.
EOF

  # ---------------------------------------------------------------- 2
  step "Broadcast vs unicast: what a third host actually sees"
  why <<'EOF'
  All three hosts share one broadcast domain, but the bridge only *floods* frames whose
  destination it does not know (and broadcasts). h1's ARP request for h2 is a broadcast,
  so h3 reads it. The ARP reply and the ICMP echo that follow are unicast to h1's MAC,
  so the bridge delivers them only to h1's port. h3 sees exactly one of the three frames.
EOF
  predict <<'EOF'
  h1 pings h2 once. Capturing on h3/eth0, which frames appear on h3's wire?
  a) ARP req + ARP reply + ICMP both ways  b) only the ARP request  c) only the ICMP  d) none
  answer b
  because the ARP request is broadcast (flooded to every port); everything after it is
  unicast and the bridge forwards unicast only to the matching port.
EOF
  cap h3 eth0 3 h1 ping -c1 -W1 10.0.0.2
  expect "ff:ff:ff:ff:ff:ff" "h3 heard the broadcast ARP request" "no broadcast frame reached h3"
  run sw bridge fdb show br br0
  expect "02:00:00:00:00:01" "the bridge learned h1's MAC onto a port" "bridge did not learn h1's MAC (ping succeeded?)"
  note <<'EOF'
  After the ping the bridge's forwarding database lists h1's and h2's MACs and the ports
  they were seen on. Ask yourself: where in the hex is the broadcast MAC vs h1's own MAC?
  Broadcast domains are *not* the same as "who can sniff me".
EOF

  # ---------------------------------------------------------------- 3
  step "Honest resolve: our tool vs the arping oracle"
  why <<'EOF'
  resolve_addr sends one ARP request and accepts a reply whose binding rules hold
  (RFC 826: sender protocol address == what we asked, Ethernet src == ARP sender
  hardware, target == our address). A clean reply is printed as "Unicast reply".
EOF
  cmd "sudo lab/ex h1 arp -i eth0 -c1 10.0.0.2"
  t_run h1 arp -i eth0 -c1 -W1000 10.0.0.2
  expect "[02:00:00:00:00:02]" "the honest reply for 10.0.0.2 resolves to h2's MAC" "no valid reply accepted"
  cmd "oracle: the kernel's own arping"
  run h1 arping -I eth0 -c1 10.0.0.2
  expect "02:00:00:00:00:02" "arping agrees on the MAC"
  note <<'EOF'
  Two independent resolvers agreeing on the same MAC is your "oracle match": if they ever
  disagree on a live lab, someone is lying on the wire.
EOF

  # ---------------------------------------------------------------- 4
  step "Trust, but verify: reject a lying ARP reply"
  why <<'EOF'
  An ARP reply is just a frame; nothing cryptographically ties it to the IP it claims to
  own. The defence is internal consistency: in a real reply, the Ethernet source equals
  the ARP sender hardware address. Send a reply whose Ethernet src is 02:00:00:de:ad:be
  but whose ARP sender is h2's real MAC: the binding is contradictory, so resolve_addr
  must drop it. RFC 826 section on packet generation is explicit that these fields must
  agree.
EOF
  local log=/tmp/nt-resp.log
  local resp=""
  say "  (spawning a hostile responder on h2: mode wrong-eth-src)"
  : >"$log"
  if [[ $LEARN_TEXT == 1 ]]; then
    say "      (text mode: not actually started)"
  else
    nt_ex h2 python3 "$root/py/arp_responders.py" eth0 --target "$TARGET" \
        --mode wrong-eth-src --count 1 --timeout 8 >"$log" 2>&1 &
    resp=$!
    for _ in $(seq 1 80); do
      grep -q '^ready$' "$log" 2>/dev/null && break; sleep 0.1
    done
    sleep 0.5
  fi
  cmd "sudo lab/ex h1 arp -i eth0 -c1 10.0.0.99   (should print nothing)"
  t_run h1 arp -i eth0 -c1 -W2000 "$TARGET"
  expect_none "the lying reply was dropped -- no 'Unicast reply' from a contradictory binding"
  [[ -n $resp ]] && wait "$resp" 2>/dev/null || true
  note <<'EOF'
  Compare with the honest case: the difference is exactly one byte in eth.src vs the ARP
  sender hardware address. Real attackers forge worse than this; the tool's job is to
  demand the fields that an attacker has to lie about.
EOF

  # ---------------------------------------------------------------- 5
  step "Flood resilience: many identical replies collapse to one accepted"
  why <<'EOF'
  An attacker blasting the same correct reply is still only one binding. The tool accepts
  the first consistent reply and treats duplicates as the same answer -- otherwise a flood
  would double-count a single honest host. (The arp-flood fixture makes the same point
  offline.)
EOF
  say "  (spawning a duplicate-reply responder on h2: mode dup)"
  : >"$log"
  if [[ $LEARN_TEXT == 1 ]]; then
    say "      (text mode: not actually started)"
  else
    nt_ex h2 python3 "$root/py/arp_responders.py" eth0 --target "$TARGET" \
        --mode dup --count 1 --timeout 8 >"$log" 2>&1 &
    resp=$!
    for _ in $(seq 1 80); do
      grep -q '^ready$' "$log" 2>/dev/null && break; sleep 0.1
    done
    sleep 0.5
  fi
  t_run h1 arp -i eth0 -c1 -W2000 "$TARGET"
  local n
  n=$(printf '%s\n' "$LAST_OUT" | grep -c 'Unicast reply' || true)
  if [[ $n -eq 1 ]]; then
    say "  [check] exactly one reply accepted from two identical answers  ->  duplicates collapse"
    echo "  [check-ok] dup counted once ($n)" >> "$LEARN_LOG"
  else
    say "  [check] expected exactly one accepted reply, got $n"
    echo "  [check-miss] dup count $n" >> "$LEARN_LOG"
    MISSES+=("dup-count")
  fi
  [[ -n $resp ]] && wait "$resp" 2>/dev/null || true

  # ---------------------------------------------------------------- 6
  step "Scan the segment: who is alive is an ARP question, not a ping question"
  why <<'EOF'
  `arp scan` asks who-has for every address in the subnet at a gentle rate. A live host
  answers -- even one with a firewall that drops ICMP, because ARP sits below IP and the
  reply comes from the neighbour layer alone. That is why the ARP oracle is nmap -sn -PR
  (ping scan but `-PR`, ARP ping) rather than plain ping: we are testing L2 existence.
EOF
  cmd "sudo lab/ex h1 arp scan -i eth0 10.0.0.0/24"
  t_run h1 arp scan -i eth0 10.0.0.0/24
  expect "10.0.0.2" "h2 answered who-has"
  expect "10.0.0.3" "h3 answered who-has"
  cmd "oracle: nmap with the same ARP technique"
  run h1 nmap -sn -PR -n 10.0.0.0/24
  expect "10.0.0.2" "nmap found the same hosts"
  expect "10.0.0.3"
  note <<'EOF'
  Both tools send ARP requests and read ARP replies; nmap's -sn -PR is pure ARP-ping, no
  port work. Addresses where the two disagree are hosts that do not want to be found that
  way -- a honeypot test for this lab, never a real network.
EOF

  # ---------------------------------------------------------------- 7
  step "Poison one cache and let arpmon catch it red-handed"
  why <<'EOF'
  h3 does not own 10.0.0.2, but nothing stops it from *saying* it does. arpspoof sends h1
  a forged reply that rebinds 10.0.0.2 -> h3's MAC, so h1's cache now points at the
  attacker. arpmon, watching h1's own interface, has a baseline from the honest ARP the
  warm ping produced; the moment a known IP changes MAC it raises binding-change.
EOF
  if [[ $LEARN_TEXT == 1 ]]; then
    say "  (text mode: would start arpmon on h1, warm the cache, poison from h3, then grep the alert)"
  else
    nt_ex h1 timeout 6 env NT_LAB=1 "$BIN/arpmon" -i eth0 >/tmp/nt-wizard-armon.out 2>&1 &
    local mon=$!
    sleep 0.5
  fi
  run h1 ip neigh flush all
  run h1 ping -c1 -W1 10.0.0.2
  cmd "sudo lab/ex h3 arpspoof -i eth0 -t 10.0.0.1 -s 10.0.0.2 -n 8 -p 150"
  t_run h3 arpspoof -i eth0 -t 10.0.0.1 -s 10.0.0.2 -n 8 -p 150
  run h1 ip neigh show 10.0.0.2 dev eth0
  expect "02:00:00:00:00:03" "h1's cache now points at the attacker (poison worked)" "cache did not point at h3"
  if [[ $LEARN_TEXT == 1 ]]; then
    say "  (text mode: arpmon would print 'ALERT binding-change ip=10.0.0.2 mac=...')"
  else
    run h1 sh -c "grep 'ALERT binding-change' /tmp/nt-wizard-armon.out || true"
    expect "ALERT binding-change" "arpmon raised the alarm the moment the binding flipped"
    wait "$mon" 2>/dev/null || true
  fi
  note <<'EOF'
  Order of bytes matters: the poison is a *unicast* reply delivered only to h1, so nobody
  else on the segment can see the crime -- that is exactly why arpmon must sit on the
  victim's own interface. Defences run from the neighbour entry itself (below) to ip neigh
  policy (arp_accept/arp_ignore) and monitoring.
EOF

  # ---------------------------------------------------------------- 8
  step "Defence: a permanent neighbour refuses the rewrite"
  why <<'EOF'
  A neighbour entry pinned with nud permanent tells the kernel the mapping is admin-owned:
  ARP updates and even the kernel's own learning cannot overwrite it. The poison arrives,
  and the answer is "no". (On exit, arpspoof also hands the true mapping back -- the note
  in its own output explains the restore.)
EOF
  cmd "sudo lab/ex h1 ip neigh replace 10.0.0.2 lladdr 02:00:00:00:00:02 dev eth0 nud permanent"
  run h1 ip neigh replace 10.0.0.2 lladdr 02:00:00:00:00:02 dev eth0 nud permanent
  t_run h3 arpspoof -i eth0 -t 10.0.0.1 -s 10.0.0.2 -n 8 -p 150
  run h1 ip neigh show 10.0.0.2 dev eth0
  expect "02:00:00:00:00:02" "the permanent entry still shows h2's real MAC after another poison" "permanent entry was overwritten"
  cmd "sudo lab/ex h1 ip neigh del 10.0.0.2 dev eth0   (cleanup)"
  run h1 ip neigh del 10.0.0.2 dev eth0
  note <<'EOF'
  Permanent entries are a triple-edged tool: they defeat poisoning, but also defeat
  legitimate reconfiguration -- the knob to remember alongside arp_accept/arp_ignore and
  monitoring, not instead of them.
EOF

  # ---------------------------------------------------------------- 9
  step "Restore and batch-grade the segment"
  why <<'EOF'
  The scenario scripts are the non-interactive form of this tour: same topology, same
  attacks, no narration, PASS/FAIL per behaviour. Run them after the tour to prove none
  of your poking left the fabric dirty.
EOF
  cmd "sudo lab/up.sh bridge3 --force"
  cmd "sudo lab/scenarios-arp.sh"
  cmd "sudo lab/scenarios-spoof.sh"
  note <<'EOF'
  scenarios-arp covers the honest resolve, three hostile reply modes, the duplicate
  collapse, the 0.0.0.0 probe, and the duplicate-IP conflict during scan. scenarios-spoof
  re-runs the poison, arpmon, restore-on-exit and permanent-entry defence. Every PASS
  there is a behaviour you just watched live.
EOF

  report
}
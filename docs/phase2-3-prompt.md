Prerequisite: Phase 1 is signed off. Its decoders (`src/lib/`) are reused unchanged. If you find a Phase 1 bug,
write the failing regression test first, fix it in the library, then continue.

---

## Kickoff block (paste this)

```
PHASE: 2+3, ping (ICMPv4/v6), traceroute, ARP resolve/scan/monitor/spoof (lab only), NDP resolve
MODE: MENTOR (guided, milestone-gated; protocol: "Guided session protocol" in docs/phase2-3-prompt.md)
OWNER-OWNED CODE: packet builders in src/lib/, src/ping/, src/traceroute/, src/arp/, src/arpmon/,
                  src/arpspoof/, the reply-matching logic everywhere
AGENT MAY WRITE: the M0 spec, lab/topo/line4.sh, the NT_LAB env change in lab/ex, src/common/ plumbing
                 (guard, monotonic clock helpers, the mechanical move of shared Phase 1 code), the Makefile
                 changes for it, scapy golden-vector and hostile-responder scripts, unit-test cases, fuzz
                 harness bodies, oracle comparison scripts, docs. Never the builders, matchers or tools.
GOAL: ping and traceroute that match iputils/traceroute on the lab; an ARP resolver, scanner, monitor and
      lab-only spoofer; an NDP resolver; every reply validated against what was actually sent
TOPOLOGY: basic (ping), line4 (traceroute, new), bridge3 (ARP/NDP/spoof)
ORACLES: iputils ping, traceroute -n (-U and -I), arping -I, ip neigh, ip -6 neigh, nmap -sn -PR,
         tcpdump/tshark, my own Phase 1 sniffer, scapy
OUT OF SCOPE: ping flood, IP options (record route), TCP traceroute (Phase 7), reverse DNS (Phase 5),
              Paris/ECMP-aware traceroute, full PMTU discovery (Phase 8), proxy ARP, DAD and RA, DHCP,
              anything outside the nt-* lab
DONE WHEN: milestones M0-M13 below are all signed off by me
FIRST DELIVERABLE: M0 spec and scaffolding only. Then stop and wait for my "go".
Read AGENTS.md, README.md, docs/phase1-prompt.md and docs/phase2-3-prompt.md first. Restate the plan in
under 10 lines and wait.
```

---

## Guided session protocol (the agent follows this for every milestone)

1. **Brief** (max 15 lines): the wire format or socket semantics as an offset/size/field/notes table or a
   short sequence, RFC sections, and the two or three gotchas that bite here.
2. **Predict**: ask exactly one "predict before you run" question; the owner answers before any code.
3. **Tests first**: unit tests and, where the feature touches the wire, a scapy script that produces golden
   bytes or a hostile responder. The owner sees tests fail before implementing. The agent never writes the
   builders, matchers or tools.
4. **Owner implements.** The agent gives hints, RFC pointers and diagrams, not code. If asked for code, ask
   once: "switch to IMPLEMENT for this function?" and wait for yes.
5. **Review** the diff by severity: memory safety, then reply validation and trust, then correctness, then
   style. File:line, no rewrites unless asked.
6. **Gate**: run `make BUILD=asan test`, report the real output, then ask "Sign off M<N>?" and do not start
   the next milestone until the owner says go.

Keep replies concise. No background the owner already knows.

---

## Hard rules

**Safety and scope (active tools, non-negotiable)**
1. Every tool here sends traffic. They run only inside `nt-*` namespaces via `lab/ex`. `lab/ex` exports
   `NT_LAB=1`, and every tool calls `nt_guard()` (in `src/common/`) before sending anything. The guard
   refuses unless: `NT_LAB=1`; the target is inside `10.0.0.0/16` or the IPv6 documentation/ULA range the lab
   uses; and, for ARP and NDP tools, the interface driver is `veth` (checked with `ETHTOOL_GDRVINFO`).
   The guard is a seatbelt against typos, not a security boundary. Say so in the docs.
2. `arp scan` accepts at most a `/24`, defaults to 100 packets per second, and hard-caps at 1000. `arpspoof`
   works only on the `bridge3` topology, runs for a fixed duration (default 10 s, max 60 s), and restores the
   correct mapping on exit and on SIGINT/SIGTERM. No loops that outlive the process.
3. Ping has a minimum interval of 0.2 s. No flood mode.
4. No new `sudo` use beyond `lab/*`, `make lab-*`, and running the tools through `lab/ex`. No sysctl changes
   on the host. Sysctls inside a namespace are fine, and every experiment lists the exact command and how
   to undo it.
5. Never relay or alter traffic outside the lab. The relay experiment (M11) is an attacker namespace with
   `ip_forward` inside the lab only.

**Library additions (`src/lib/`)**
6. Builders are pure: `nt_status nt_build_x(uint8_t *out, size_t cap, size_t *outlen, const struct in *i)`.
   No malloc, no I/O, no globals. They check `cap` before every write and compute their own checksums using
   the Phase 1 `nt_csum_*` code. Never duplicate checksum logic.
7. Every builder has a round-trip test (build, then decode with the Phase 1 decoder, compare fields) and a
   golden-bytes test against scapy output stored in `fixtures/golden/`.
8. Reply validation lives in library functions (`nt_match_*`) separate from socket code, so they can be
   fuzzed and unit-tested with no sockets. A matcher returns `MATCH`, `NO_MATCH`, or `INVALID`, and the
   caller must not treat `NO_MATCH` as an error.

**Ping**
9. A reply is accepted only if all hold: ICMP type/code is echo reply, checksum valid, identifier equals
   ours, sequence is in the outstanding window, source address equals the target (or, for an error, the quoted
   original packet matches what we sent). Anything else is counted as "ignored", not printed as a reply.
10. RTT comes from a local send-time table keyed by sequence, using `CLOCK_MONOTONIC`. Never trust a timestamp
    carried in the reply payload. Verify that the echoed payload equals what was sent, and report a mismatch.
11. Raw `IPPROTO_ICMP` receives every ICMP packet in the namespace. Install `ICMP_FILTER`
    (`setsockopt(SOL_RAW, ICMP_FILTER)`) to pass only echo reply, destination unreachable, time exceeded,
    and still validate in user space. For ICMPv6 use `ICMP6_FILTER` the same way.
12. Timing uses absolute deadlines with `poll`/`ppoll`. No `sleep`-based scheduling, no drift, `EINTR`
    handled, clean exit on SIGINT with the summary (sent, received, loss, min/avg/max/mdev).
13. Provide both modes: raw socket (you build the ICMP header) and `--dgram` (`SOCK_DGRAM`, `IPPROTO_ICMP`,
    needs `net.ipv4.ping_group_range` inside the namespace). The mode difference is documented from captures.
14. Options: `-c`, `-i`, `-W`, `-s`, `-t` (TTL), `-M do` (DF set via `IP_MTU_DISCOVER`), `-6`. Destination
    unreachable and TTL exceeded replies are printed with their code names, including "fragmentation needed,
    next-hop MTU N".
15. ICMPv6: raw `IPPROTO_ICMPV6` socket. The kernel computes the ICMPv6 checksum (pseudo-header) for you. Prove
    that with a capture instead of assuming it, and write down why the checksum covers IP addresses.

**Traceroute**
16. Send probes sequentially: one hop at a time, N probes per hop (default 3), per-probe timeout (default 1 s),
    max TTL default 30. Set TTL with `IP_TTL` on the send socket.
17. UDP mode: a UDP datagram socket sends to destination port `33434 + probe index`, fixed per-run source port.
    Replies are read from a raw ICMP socket with the filter from rule 11.
18. Matching uses the quoted original packet inside the ICMP error. Parse it with bounds checks: quoted IPv4
    header (validate IHL and protocol), then at least 8 bytes of the UDP header (RFC 792 minimum, though modern
    routers may quote more per RFC 1812). Match source port, destination port and destination address against
    outstanding probes. A reply that does not match is ignored, never attributed to a hop.
19. Interpret: type 11 code 0 = hop reached; type 3 code 3 = destination reached (UDP); type 3 other codes are
    printed as `!N`, `!H`, `!P`, `!F`, `!X` style annotations; code 4 shows the next-hop MTU.
20. Output: numeric only, one line per hop, repeated addresses collapsed, `*` for timeout, RTT per probe.
    Different responders within one hop are all printed.
21. ICMP mode (`-I`): echo probes with a fixed identifier and incrementing sequence; destination reached on echo
    reply. The matching logic is shared with ping where possible.

**ARP and NDP**
22. ARP socket: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))`, bind to the ifindex, send complete Ethernet
    frames padded to 60 bytes. Reuse the Phase 1 ARP decoder for receive.
23. A reply is accepted only if: op is reply, sender IP equals the IP we asked about, target hardware and IP
    match our request, and ARP sender MAC equals the Ethernet source MAC. Count and report any reply that fails
    the Ethernet/ARP MAC consistency check.
24. Resolve has retries with backoff (default 3 tries, 500 ms), a `--probe` mode using sender IP `0.0.0.0`
    (RFC 5227 style, no cache pollution), and prints the elapsed time. It never writes to the kernel
    neighbor table.
25. Scan: send is paced by a deadline loop, receive uses the same `poll` loop, then a grace period (default 2 s)
    after the last send. Results live in a fixed array indexed by host number, never grown from wire input.
    Report duplicates, and flag one IP answered by two different MACs.
26. Monitor (`arpmon`) keeps a bounded binding table (fixed capacity, LRU eviction; an attacker flooding fake
    bindings must not exhaust memory). Alerts, each rate-limited: binding changed, flip-flop, reply without a
    matching request, gratuitous ARP for a known IP, Ethernet/ARP MAC mismatch, duplicate IP. It runs from a
    pcap (`-r`) and live (`-i`), with the same detection code.
27. `arpspoof` sends unsolicited replies to one named victim, targets one named IP, and restores the real
    mapping at exit using the real MAC learned by resolving it first. Owner writes it, the agent reviews it
    under the safety rules above.
28. NDP: craft Neighbor Solicitation to the solicited-node multicast address through a raw ICMPv6 socket with
    hop limit 255 (`IPV6_MULTICAST_HOPS`). On receive, request the hop limit with `IPV6_RECVHOPLIMIT` and accept
    a Neighbor Advertisement only if hop limit equals 255 (RFC 4861 section 7.1). Explain in your write-up what
    attack that single check stops.

**Process**
29. `BUILD=asan` by default, zero warnings. No new dependencies. No libpcap, no libnet, no
    `<netinet/ip_icmp.h>` structs for decoding.
30. Privileges: open the sockets first, then drop capabilities before parsing any received bytes. Check with
    `grep Cap /proc/<pid>/status`. `arpspoof` and `arp scan` keep nothing after the socket opens.
31. Every milestone adds hostile cases next to happy-path ones (see "Hostile fixtures" below).
32. Every claim of success comes with the command and its real output. If something needs root, give the exact
    command and the expected result.
33. Stay in scope. New ideas go on the "later" list in `docs/phase2-3.md`.

---

## Milestones (each ends with the protocol gate)

| # | Deliverable | Owner implements | Agent provides | Predict before you run | Sign-off test |
|---|---|---|---|---|---|
| M0 | Spec and scaffolding | nothing | one-page spec (wire tables for ICMP echo/error, ARP, NS/NA; socket-mode table; matcher contracts), `lab/topo/line4.sh` (h1 - r1 - r2 - h2), `NT_LAB=1` in `lab/ex`, `src/common/` with guard and clock helpers, Makefile hook for it | What source address will h1 see on a TTL-exceeded from r1: r1's h1-facing or h2-facing address? | spec approved, `make phase0` still green, `lab/up.sh line4` passes ping |
| M1 | Builders | `nt_build_icmp_echo`, `nt_build_arp_frame`, `nt_build_icmp6_ns` | golden vectors from scapy, round-trip tests, builder-overflow cases (`cap` too small) | Which bytes does the ICMP checksum cover, and does it include the IP header? | round-trip and golden tests green, ASan clean |
| M2 | Ping v4, raw | send/recv loop, reply validation, RTT table, summary | hostile responder (`py/responders.py`: wrong id, wrong seq, wrong source, bad checksum, duplicate reply) | What TTL does the reply show on `basic` h1 to h2 versus h1 to rtr, and why? | RTT/loss in line with `ping -n`; every hostile reply ignored and counted |
| M3 | Ping extras | `-s -t -M do -W -i`, `--dgram`, `ICMP_FILTER`, error decoding | scenarios: MTU 1400 link via `ip link set mtu`, DF + large `-s` | In `--dgram` mode, is the identifier on the wire the one you chose? | frag-needed with next-hop MTU printed; capture diff raw vs dgram documented |
| M4 | Ping v6 | `-6`, `ICMP6_FILTER`, hop-limit display | IPv6 addresses added to `basic` (agent adds `fd00:1::/64`, `fd00:2::/64`) | Who computes the ICMPv6 checksum, you or the kernel? | `-6` works across the router; capture proves checksum is valid on the wire |
| M5 | Traceroute UDP | probe loop, TTL setting, quoted-header matcher, hop output | line4 oracle script comparing to `traceroute -n -U` | At which hop does the destination answer with type 3 code 3, and why that code? | hop list matches the oracle on `basic` and `line4` |
| M6 | Traceroute ICMP and codes | `-I` mode, `!N/!H/!P/!F/!X` annotations, MTU display | scenarios: route removed on r2 (`!N`), nft reject rule on r1 (`!X`), DF with small MTU | What does a router with no route for the destination send back, and from which address? | each scenario produces the expected annotation; `-I` matches `traceroute -n -I` |
| M7 | ARP resolve and probe | resolve with retries, `--probe` mode, validity checks | scapy hostile responder: wrong sender IP, wrong Ethernet src, wrong target | Does a probe with sender `0.0.0.0` change the target's neighbor entry? | MAC equals `arping -I` output; kernel table unchanged; hostile replies rejected and counted |
| M8 | ARP scan | paced sender, receive loop, results array, duplicates flag | `bridge3` with a duplicate-IP host added by script | How many ARP replies does h1 receive if h3 has two interfaces with the same IP? | results match `nmap -sn -PR` on `10.0.0.0/24`; rate cap verified with a capture |
| M9 | NDP resolve | NS builder use, raw ICMPv6 socket, hop-limit check | scapy NA with hop limit 64 (must be rejected) | Why must NS/NA hop limit be 255? | MAC matches `ip -6 neigh` entry; hop-limit-64 NA rejected |
| M10 | ARP monitor | bounded binding table, detection rules, `-r` and `-i` modes | `py/gen_arp_attack.py` -> `fixtures/arp-spoof.pcap`, `arp-flood.pcap` (thousands of fake bindings) | A bystander on a bridge: can it see unicast ARP replies between two other hosts? | each rule fires on its fixture; memory stays flat on the flood fixture |
| M11 | Spoof and defend (lab only) | `arpspoof`, guard integration, restore-on-exit | experiment script: poison h1's entry for h2 from h3, with and without `ip_forward` on h3, defences | Does Linux accept an unsolicited ARP reply for an IP that is not yet in the cache? Does `arp_accept` change it? | monitor detects the attack live; each defence tested (see below) and documented; mapping restored after exit |
| M12 | Hardening | fixes only | `fuzz_icmp_error.c`, `fuzz_arp.c`, `fuzz_ns_na.c` bodies; seed corpus script | Which parser is most likely to hit an out-of-bounds read first: the ICMP-error quote or ARP? | 5 minutes of fuzzing per target, no findings; all hostile fixtures rejected; capabilities dropped after socket open |
| M13 | Lab validation and write-up | `docs/phase2-3.md` | experiment run script, review against `docs/phase-template.md` | With `net.ipv4.icmp_ratelimit` raised, do the stars in your traceroute go away? | oracle results, break-and-debug, security note, later-list all present |

### Defences to test in M11 (inside the lab only; every command printed with its undo)

- `ip neigh replace <ip> lladdr <mac> dev eth0 nud permanent` on the victim
- `arp_ignore`, `arp_announce`, `arp_filter`, `arp_accept` sysctls on the relevant namespace
- bridge port isolation (`bridge link set dev <port> isolated on`) and what it changes
- your monitor from M10 running on the victim, and on the bridge via a `tc mirred` mirror

---

## Hostile fixtures (the agent writes the generators; the owner's tools must survive all of them)

**ICMP/traceroute:** truncated error quote (fewer than 28 bytes), quoted IHL below 5 or beyond the packet, quoted
protocol not UDP/ICMP, quote matching a different flow, reply from an unexpected address, type 11 with a bad ICMP
checksum, echo reply with right id and wrong sequence, duplicate replies, replies after the deadline, oversized
payload.

**ARP/NDP:** hlen or plen not 6/4, htype not 1, ptype not 0x0800, op 0 and op above 2, sender MAC different from
Ethernet source, broadcast sender MAC, truncated frames, reply to a request that was never sent, NA with hop limit
below 255, NA with bad checksum, NA for a different target address.

---

## Gotchas cheat sheet (the agent raises each one at the milestone it belongs to, not before)

- **Raw ICMP socket sees everything** in the namespace. Filter by id/seq, and remember the kernel answers
  echo requests itself (`icmp_echo_ignore_all` changes this).
- **Raw receive includes the IPv4 header; `SOCK_DGRAM` ICMP does not.** For `SOCK_DGRAM` the kernel rewrites the
  identifier and checksum.
- **ICMPv6 checksum includes a pseudo-header.** The kernel fills it in on raw ICMPv6 sockets; ICMPv4 has no
  pseudo-header.
- **TTL-exceeded replies come from the router's ingress interface address**, so hop addresses are the near-side
  interfaces. Compare against `ip route get` on each router.
- **ICMP error rate limiting** (`net.ipv4.icmp_ratelimit`, `icmp_ratemask`) produces stars on fast probing; keep
  probes sequential.
- **Quote length varies.** RFC 792 guarantees only the IP header plus 8 bytes; do not assume more.
- **`rp_filter`** drops packets whose source would not be routed back out the receiving interface; relevant for
  asymmetric `line4` experiments.
- **AF_PACKET sends do not pad.** Pad ARP frames to 60 bytes yourself, otherwise strict receivers drop them.
- **ARP flux:** with the default `arp_ignore=0`, Linux answers for any local IP on any interface.
- **Bystanders see broadcast ARP only.** Unicast replies are visible to the two endpoints and, on a bridge, only
  if flooded or mirrored; place the monitor accordingly.
- **Gratuitous ARP semantics** differ by kernel setting: whether an unsolicited reply creates, updates or is
  ignored depends on `arp_accept` and whether an entry exists.
- **NDP security rests on hop limit 255**, which no off-link host can produce.
- **Veth checksum offload** can show bad outgoing checksums in captures; the lab keeps offloads off unless
  `NT_OFFLOAD=1`.

---

## Definition of done (all must be true)

- [ ] M0-M13 each signed off in the conversation
- [ ] `make BUILD=asan test` and `make san-test` green, zero warnings
- [ ] `make fuzz` run 5 minutes per target with no findings, corpus saved under `fuzz/corpus/`
- [ ] ping output matches iputils on `basic` for RTT/loss/TTL; every hostile responder case ignored and counted
- [ ] traceroute hop list matches `traceroute -n -U` and `-I` on `basic` and `line4`; each `!` annotation reproduced
- [ ] ARP resolve matches `arping -I`; scan matches `nmap -sn -PR`; NDP resolve matches `ip -6 neigh`
- [ ] `arpmon` fires each rule on its fixture and live during the M11 attack; memory stays flat on the flood fixture
- [ ] guard demonstrated: tools refuse outside `lab/ex`, with a non-veth interface, and for out-of-range targets
- [ ] capabilities dropped after socket open, verified with `grep Cap /proc/<pid>/status`
- [ ] break-and-debug write-up (at least two) and security note in `docs/phase2-3.md`, including the NDP
      hop-limit explanation and which M11 defences worked and why
- [ ] time spent within the 2-3 week box; overruns noted with the cause

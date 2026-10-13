# Phase 4+5+6 guided metaprompt: sockets, DNS, DHCP

Save as `docs/phase4-6-prompt.md` in the repo. Paste the kickoff block as the first message of each sub-phase.
It extends `AGENTS.md` and builds on `docs/phase1-prompt.md` and `docs/phase2-3-prompt.md`. Where they conflict,
the `AGENTS.md` safety rules win.

Prerequisite: Phase 2+3 signed off. Reused unchanged: the Phase 1 decoders and `nt_csum_*`, the Phase 2+3 builders,
`nt_guard()`, `lab/ex` (`NT_LAB=1`), `src/common/`, `scripts/tshark-fields.sh`. If any of these is missing, stop and
report; do not recreate it.

Work the sub-phases in order and start a fresh agent session for each one, with SUB-PHASE set in the kickoff block.
That keeps context small and gives each sub-phase its own write-up.

| Sub-phase | Build | Time-box |
|---|---|---|
| 4 | `ncx` (netcat clone), `echod` (epoll TCP/UDP echo server), handshake/teardown/queue/timer experiments | ~1 week |
| 5 | DNS wire codec in `src/lib/`, `dnsq` stub resolver, iterative walk from lab root hints | ~2 weeks |
| 6 | DHCP codec in `src/lib/`, `dhcpc` DORA client over a raw socket, rogue-server and starvation experiments | ~1 week |

---

## Kickoff block (paste this)

```
PHASE: 4+5+6, sockets, DNS, DHCP
SUB-PHASE: <4 | 5 | 6>   (work only this one; milestones are listed in docs/phase4-6-prompt.md)
MODE: MENTOR (guided, milestone-gated; protocol: "Guided session protocol" in docs/phase4-6-prompt.md)
OWNER-OWNED CODE:
  4: src/ncx/, src/echod/ (all socket and event-loop logic), sniff --tcp-trace formatting
  5: DNS codec, matcher, classifier in src/lib/; src/dnsq/ (stub, TCP fallback, iterative walk); sniff --dns printer
  6: DHCP codec, builders, matchers in src/lib/; src/dhcpc/ (state machine, raw socket); sniff --dhcp printer
AGENT MAY WRITE: the M0-style spec for the sub-phase, lab topologies and service configs (nsd, unbound, dnsmasq),
                 lab/svc.sh, lab/apply-lease.sh, scapy/Python scripts (hostile peers, load generators, spoofers,
                 fixtures), unit-test cases, fuzz harness bodies, oracle scripts, Makefile hooks, docs.
                 Never the codecs, matchers, classifiers, event loops, resolver or DHCP logic.
GOAL: see the sub-phase section; every behavior verified against an oracle and a capture
TOPOLOGY: 4: basic, line4. 5: dnslab (new). 6: dhcp1 (new), bridge3 for the rogue server
ORACLES: ss, nstat, tcpdump/tshark, my sniffer, scapy; dig, unbound, nsd (5); dnsmasq log and lease file,
         dhclient or udhcpc, tshark -Y bootp (6)
OUT OF SCOPE: see the sub-phase section
DONE WHEN: all milestones of this sub-phase are signed off by me, and its docs/phase<N>.md exists
FIRST DELIVERABLE: the sub-phase's spec milestone only. Then stop and wait for my "go".
Read AGENTS.md, README.md, docs/phase1-prompt.md, docs/phase2-3-prompt.md and docs/phase4-6-prompt.md first.
Restate the plan in under 10 lines and wait.
```

---

## Guided session protocol (the agent follows this for every milestone)

1. **Brief** (max 15 lines): wire format as an offset/size/field/notes table, or the socket behavior as a short
   sequence; RFC sections; the two or three gotchas that bite here.
2. **Predict**: ask exactly one "predict before you run" question; the owner answers before any code.
3. **Tests first**: unit tests with hand-built bytes, and a scapy/Python peer or hostile responder where the
   feature touches the wire. The owner sees them fail before implementing. The agent never writes the owner-owned code.
4. **Owner implements.** The agent gives hints, RFC pointers and diagrams, not code. If asked for code, ask once:
   "switch to IMPLEMENT for this function?" and wait for yes.
5. **Review** the diff by severity: memory safety, then trust of remote input, then resource limits, then
   correctness, then style. File:line, no rewrites unless asked.
6. **Gate**: run `make BUILD=asan test`, report real output, then ask "Sign off M<N>?" and do not start the next
   milestone until the owner says go.

Keep replies concise. No background the owner already knows.

---

## Hard rules

### A. Safety and scope (all sub-phases, non-negotiable)

1. Every tool runs only inside `nt-*` namespaces via `lab/ex` and calls `nt_guard()` before any socket use.
   Allowed peers: `10.0.0.0/16`, the lab IPv6 range, and loopback inside the namespace. Servers (`echod`, test
   daemons) refuse to start without an explicit `--bind <lab address>`.
2. No tool ever executes anything: no `system`, `popen`, `exec*`, no shell, and `ncx` has **no `-e`/`-c` option**.
   Anything that must run commands (applying a DHCP lease) is a script under `lab/`, not a C tool.
3. Libc name resolution (`getaddrinfo`, `gethostbyname`) is never called. Sub-phase 4 tools take numeric addresses
   only (`inet_pton`). Names go through your own resolver, and only inside the lab.
4. Every flood, load, spoof or starvation script is bounded and prints its bounds first: at most 5000 packets, 1000
   connections, 32 DHCP exchanges, 30 s for any spoof run. No unbounded loops, no `--flood`, `hping3` always with `-c`.
5. Sysctls are changed only inside the namespace. Before changing one, prove it is per-namespace
   (`ip netns exec nt-h1 sysctl <key>`), print the exact command and its undo, and never touch the host value.
   Tools never write to `/proc` or `/sys`.
6. No real-internet traffic. The root of the DNS walk is the lab root. Studying real-world behavior (`dig +trace`
   against public roots) is something the owner does by hand, outside the agent session.
7. New dependencies need approval: `nsd`, `unbound`, `dig`, `hping3`, `udhcpc`/`dhclient`. The agent asks once in
   the spec milestone. If declined, fall back to scripted servers in `py/`, and say which oracle is lost.
8. All remote data is untrusted: names, hostnames, option values and payloads are escaped (non-printable bytes as
   `\xNN`, dots inside DNS labels as `\.`) before printing, and never reach a shell or a format string.

### B. Sockets (sub-phase 4)

9. Every syscall result is checked. `EINTR` is retried, `EAGAIN` is told apart from real errors, short reads and
   writes are handled (loop when blocking, per-connection pending buffer when not). Never assume one `send` equals
   one `recv` on TCP.
10. SIGPIPE is ignored and sends use `MSG_NOSIGNAL`. All fds are created with `CLOEXEC`/`accept4` flags. A leak
    check (fd count before and after a run) is part of every test.
11. `ncx` is numeric-only, no exec, and its EOF behavior is specified in M0: default keeps the socket open until
    the peer closes; `-N` calls `shutdown(SHUT_WR)` on stdin EOF. Exit codes are defined in the spec.
12. `echod` is single-threaded `epoll`, with nonblocking sockets, `accept4`, and a connection slab allocated at
    startup (no per-connection `malloc`) with a `max_conns` cap (default 1024). Level-triggered is the default.
    Edge-triggered (`--et`) is an experiment and must drain until `EAGAIN`, including the accept loop.
13. Backpressure: when a connection's output buffer is full, stop reading from it (drop `EPOLLIN`, arm `EPOLLOUT`).
    Never grow buffers, never block the loop, never drop echoed data silently.
14. Limits: idle timeout (default 30 s, driven by `timerfd`), at-capacity policy chosen from {stop accepting,
    accept-and-close}, justified in `docs/phase4.md` and tested with the flood script. `EMFILE`/`ENFILE` on `accept`
    must not cause a busy loop (spare-fd trick or temporarily stop accepting).
15. Half-close: on read EOF, flush pending output, then `shutdown(SHUT_WR)`; close only after the peer closes or the
    idle timeout fires. Closing with unread received data makes the kernel send RST, so test for that explicitly.
16. Shutdown: SIGINT/SIGTERM via `signalfd` in the epoll set; stop accepting, flush, close, then print stats
    (accepted, closed by cause: peer FIN, RST, timeout, error; bytes; peak connections).
17. The socket-option table from M0 is the only place options are set: `SO_REUSEADDR` (listener, default on),
    `SO_REUSEPORT` (experiment only), `TCP_NODELAY`, `TCP_QUICKACK`, `TCP_CORK`/`MSG_MORE`, `SO_LINGER{1,0}`,
    `SO_KEEPALIVE` with `TCP_KEEPIDLE/INTVL/CNT`, `SO_RCVBUF`/`SO_SNDBUF`, `IPV6_V6ONLY` (always explicit).
18. Privileges: ports are 1024 or higher, so no capabilities are needed. Call `prctl(PR_SET_NO_NEW_PRIVS, 1)` at
    startup and drop every capability before serving.
19. UDP: receive buffer of 65535 bytes, use `recvmsg` and check `MSG_TRUNC`, treat each datagram as a unit.
20. **Three views must agree**: every experiment compares tool output, kernel view (`ss -tan`/`ss -ltn`/`nstat`), and
    a capture (`sniff --tcp-trace` or tcpdump). Differences are explained before sign-off.

### C. DNS (sub-phase 5)

21. Library (`src/lib/`): pure, bounded, no `malloc`, no I/O, no globals, and no randomness (the caller supplies the
    transaction id). Statuses are the Phase 1 set; each failure class is tested separately.
22. Message decode: the 12-byte header, then validate section counts against the remaining length *before* looping
    (each question needs at least 5 bytes, each RR at least 11). Section caps are compile-time constants; exceeding
    them returns `NT_ERR_UNSUPPORTED`. More than one question is `UNSUPPORTED`. A response with opcode other than
    QUERY is rejected.
23. Names: labels are 0 to 63 bytes; label type bits `01`/`10` are reserved and malformed. A compression pointer
    must point strictly backward and not into the header. Expansion has a hop cap (128) and a total wire length cap
    (255) as belt and braces. Pointer offsets are relative to the start of the DNS message, so for TCP they exclude
    the 2-byte length prefix. Wire names are never C strings (a label may contain NUL or dots).
24. Comparison is ASCII case-insensitive only (A-Z), never locale-dependent. Suffix tests are by label boundary
    (`ample.test` is not a parent of `example.test`).
25. RDATA: decode A (4 bytes), AAAA (16), NS/CNAME/PTR (one name), MX, SOA, TXT (character-strings), OPT; keep all
    other types opaque. For compressible types the name must end exactly at RDLENGTH. RDLENGTH beyond the message,
    or inconsistent with the content, is `MALFORMED`.
26. EDNS0: at most one OPT, owner name is root, class is the UDP payload size (values below 512 count as 512), TTL
    carries extended RCODE (8 bits), version (8) and the DO bit. The full RCODE is the header's 4 bits plus the
    extended 8 bits. A second OPT is `MALFORMED`.
27. Builder: `nt_build_dns_query` validates the name (labels 1 to 63, wire length at most 255, no empty labels, `\DDD`
    escapes), writes one question, and optionally OPT (default size 1232, DO optional). RD is a parameter.
28. Matcher `nt_dns_match` returns `MATCH`, `NO_MATCH` or `INVALID`: QR=1, opcode, id, one question equal to the one
    sent (name, type, class). The tool additionally enforces source address and port.
29. Classifier `nt_dns_classify` decides from the sections, not from AA alone: `ANSWER`, `CNAME` (next name),
    `NODATA`, `NXDOMAIN`, `REFERRAL`, `TRUNCATED`, `SERVFAIL`, `REFUSED`, `BOGUS`. Answer records count only if the owner is
    the qname or a CNAME target in the same message (chain cap 8, loops are `BOGUS`). A referral counts only if the
    authority NS owners are ancestors of the qname, strictly deeper than the zone just queried, and glue is used
    only for names that appear in that same message's NS set. Everything else in the additional section is ignored.
30. Stub (`dnsq`): a new socket per query, id from `getrandom(2)`, source port from `bind(0)` (the kernel
    randomizes it; confirm in a capture), connected UDP socket. Invalid or mismatched packets are ignored
    and the wait continues until the deadline; counters per reason are printed. Never use `rand()`, `time()` or
    counters for ids or ports. Receive buffer is larger than the EDNS size advertised, and an oversize datagram is
    counted and rejected.
31. TC=1 means "retry over TCP": the truncated message is not used. TCP framing is a 2-byte big-endian length; read
    exactly that many bytes under a deadline, with a 65535 cap; the response must still pass the matcher.
32. Limits for the walk: referral depth 16, CNAME chain 8, total queries 32, wall-clock deadline 10 s, and a
    repeated (server, qname, qtype) triple is `BOGUS`. IPv4 transport only; AAAA is decoded and shown. No caching.
33. `--weak` (sequential id, fixed source port) exists only for the spoof demonstration, prints a loud banner on
    every run, and refuses to run outside the lab.
34. Sniffer: `sniff --dns` prints decoded DNS for UDP and TCP port 53 (no TCP reassembly: a segment that does not hold
    the full message is reported as partial). Its output is checked by a separate `scripts/tshark-dns.sh`;
    Phase 1's `--tsv` columns do not change.

### D. DHCP (sub-phase 6)

35. Library: `nt_dhcp_decode` takes the UDP payload. Fewer than 240 bytes is `TRUNCATED`; wrong magic cookie
    (`63 82 53 63` at offset 236) is `MALFORMED`; `htype` 1 requires `hlen` 6 and `hlen` is never above 16. Options are
    walked: PAD is one byte, END stops the walk (and a missing END is `MALFORMED`), anything else is code/len/data
    with the length checked against the buffer.
36. Strict option checks: option 53 length 1 and a known value, 54/50/51/58/59/1 length 4, 3/6 a non-zero multiple of 4.
    A repeated option is `MALFORMED`. Option 52 (overload) is `UNSUPPORTED`, and so is long-option concatenation
    (RFC 3396). Both are documented and tested.
37. Builders write into `(out, cap, &outlen)`, check `cap` before each write, and use the library checksums.
    `nt_build_eth_ipv4_udp` builds the full frame (Ethernet, IPv4 with header checksum, UDP with checksum). The DHCP
    payload is zero-padded after END to at least 300 bytes.
38. Matchers `nt_dhcp_match_offer` / `nt_dhcp_match_ack` return `MATCH`/`NO_MATCH`/`INVALID`: op=2, xid, chaddr, the
    expected message type, server identifier present, yiaddr non-zero. Wrong xid or chaddr is `NO_MATCH`, not an error.
39. `dhcpc` uses `AF_PACKET`/`SOCK_RAW`/`ETH_P_IP` bound to the interface, because before configuration the client has
    no IP. It sends from `0.0.0.0:68` to `255.255.255.255:67` with Ethernet destination broadcast. On receive it uses
    the Phase 1 decoders, requires UDP 67 to 68, checks IP and UDP checksums (UDP zero is allowed), skips
    `PACKET_OUTGOING` frames, and validates in user space (no BPF in this phase).
40. Timers use `ppoll` with absolute deadlines; backoff 4 s, 8 s, 16 s with ±1 s jitter from `getrandom` (the
    default can be lowered for the lab). Retransmissions keep the same xid and update `secs`; a restart after a NAK
    uses a new xid.
41. Offer handling: after the first valid OFFER, wait the offer window (default 500 ms) for others. Print every offer,
    warn when more than one server id answered, select by policy (`first` default), and honor `--trust-server <ip>`
    (offers from other servers are ignored and counted).
42. REQUEST is broadcast with options 53=3, 50 (requested IP) and 54 (server id). ACK handling checks yiaddr against the
    request, lease time present and non-zero, mask contiguous, router on-link, no loopback, multicast or broadcast
    addresses. The tool prints `lease_valid=0` with the reasons instead of trusting a bad lease.
43. Output is `key=value` lines (ip, mask, router, dns, domain, lease, server, t1, t2). Free-text options (hostname,
    domain, message) are escaped and truncated to 64 characters.
44. `lab/apply-lease.sh` validates every field with a strict regex (IPv4 dotted quad, numeric ranges), uses no `eval`,
    quotes every expansion, and only runs `ip` against `nt-*` namespaces. Hostile lease files (`;`, `$()`, newlines,
    backticks) must be refused, and a test proves it.
45. `--chaddr` lets the client identifier differ from the interface MAC (to demonstrate chaddr versus Ethernet source).
    It is allowed only inside the lab and is printed in the run header.

### E. Process (all sub-phases)

46. `BUILD=asan`, zero warnings, no new dependencies beyond rule 7, no libpcap or libnet, no packed-struct overlays.
47. Raw-socket tools open the socket first, then drop capabilities before parsing received bytes (`grep Cap
    /proc/<pid>/status`). `ncx`, `echod`, `dnsq` need none.
48. Every milestone adds hostile cases next to happy-path ones (see "Hostile fixtures").
49. Every claim of success comes with the command and its real output. If something needs root, give the exact
    command and the expected result.
50. Stay in scope. New ideas go on the "later" list in `docs/phase<N>.md`.

---

## Sub-phase 4: sockets (M0-M8)

**GOAL:** an `ncx` that behaves like `nc` for TCP/UDP, and an `echod` that survives slow, abusive and vanishing clients,
plus a measured understanding of handshake, teardown, queues, TIME_WAIT and Nagle.
**OUT OF SCOPE:** TLS, threads, io_uring, HTTP, port scanning (Phase 7), exec options, name resolution, SCTP, Unix
sockets, `sendfile`/`splice`, `SO_REUSEPORT` load balancing beyond the experiment.

| # | Deliverable | Owner implements | Agent provides | Predict before you run | Sign-off test |
|---|---|---|---|---|---|
| M0 | Spec and scaffolding | nothing | one-page spec: `ncx` behavior table (modes, flags, EOF semantics, exit codes), `echod` architecture (per-connection state, event flow, limits policy), socket-option table, experiment list with the three views; `py/loadgen.py`, `py/slowclient.py` (bounded); `nt_guard` extended for numeric lab peers | Which side ends in TIME_WAIT when the server closes first, and for how long on Linux? | spec approved, `make phase0` still green |
| M1 | `ncx` TCP | connect and listen modes, `poll` between stdin and socket, partial I/O, `-N` | peer scripts: EOF cases, 64 MiB transfer, reset mid-transfer | When stdin hits EOF, should `ncx` close, `shutdown(SHUT_WR)`, or keep waiting? What does the peer observe in each case? | 64 MiB both directions identical (`sha256sum`); EOF cases match the spec |
| M2 | `ncx` UDP, IPv6, source bind | `-u`, `-6`, `-s`, `-p`, connected vs unconnected UDP | closed-port and large-datagram scenarios | `connect()` a UDP socket to a closed port and `send()` twice: which call fails with ECONNREFUSED, and why not the first? | behavior matches the prediction; ICMP port unreachable visible in the sniffer |
| M3 | Handshake, teardown, RST | `sniff --tcp-trace` (one line per segment: relative seq/ack, flags, window, length, options), `--linger0` | state-sampling script (`ss -tan` with timestamps) | After connecting to a closed port, which flags and ack number come back? | state diagram from observation matches capture and `ss`; RST reproduced three ways: closed port, `SO_LINGER{1,0}`, data after peer close |
| M4 | `echod` core | epoll level-triggered loop, `accept4`, slab, partial writes, UDP echo socket | 1000 sequential and 100 concurrent connection scenarios | With level-triggered epoll and a listener you never `accept()` from, what does `epoll_wait` do? | 100 concurrent clients echo correctly; ASan clean; no leaked sockets |
| M5 | `echod` robustness | backpressure, `EMFILE` handling, capacity policy, idle timeout, `signalfd`, half-close flush, `--et` | slow-client suite (no-read, slow-read, slow-write, idle), flood script (at most 1000 conns) | A client sends 1 MiB and never reads: what happens to server memory, the client's `send()`, and the kernel buffers? | slow clients cannot exhaust memory or fds; fd count returns to baseline; LT and ET produce identical echo; `strace -c` comparison recorded |
| M6 | Listen queues and TIME_WAIT | `--backlog`, `--no-accept`, `--reuseaddr` on/off, port-exhaustion client | queue-overflow scripts (`tcp_abort_on_overflow`, bounded SYN burst with `hping3 -c`, SYN cookies), quick-restart script, narrowed `ip_local_port_range` run | What does the client of the overflowing connection see: RST, an error, or silence? What does `tcp_abort_on_overflow=1` change? | accept queue size (backlog+1) reproduced with `ss -ltn` and `nstat`; TIME_WAIT 60 s observed; `EADDRINUSE` and `EADDRNOTAVAIL` each reproduced and explained |
| M7 | Latency and UDP semantics | `--nodelay`, `--quickack`, `--cork` flags; UDP truncation handling; optional keepalive run | Nagle with delayed ACK scenario, stream vs datagram boundary scenario, 3000-byte datagram scenario | Two 1-byte `send()` calls back to back: when does the second segment hit the wire, and what does `TCP_NODELAY` change? | latency with and without each option measured; fragments visible in `sniff` (first has the UDP header, later ones do not) |
| M8 | Hardening and write-up | fixes, `docs/phase4.md` | `tc netem` fault runs (loss, delay, reorder inside a namespace), review against `docs/phase-template.md` | none | see Definition of done |

---

## Sub-phase 5: DNS (M9-M17)

**GOAL:** a DNS wire codec, a stub resolver with UDP/EDNS0/TCP fallback, and an iterative walk from the lab root,
validated against `dig` and `unbound`, with the failure and forgery cases understood.
**OUT OF SCOPE:** caching, DNSSEC validation, DoT/DoH, serving recursion, AXFR/IXFR, EDNS options beyond OPT basics,
mDNS/LLMNR, `resolv.conf`/search domains, IPv6 transport, parallel racing, QNAME minimization (observe `unbound`
doing it, do not implement).

**Lab (`dnslab`):** `c1` 10.0.5.10, `root` 10.0.5.1, `tld` 10.0.5.2, `auth` 10.0.5.3, `rec` 10.0.5.53 (unbound), `evil`
10.0.5.66, all on one bridge. Zones: `.` delegates `test.`; `test.` delegates `example.test.` (with glue) and
`corp.test.` (to `ns.other.test.`, no glue, for the optional glueless stretch); `example.test.` holds A, AAAA, CNAME,
a CNAME chain, MX, a short TXT, a 3000-byte TXT, a 63-byte label, and a wildcard.

| # | Deliverable | Owner implements | Agent provides | Predict before you run | Sign-off test |
|---|---|---|---|---|---|
| M9 | Spec and scaffolding | nothing | one-page spec (header flag bit table, name encoding and compression, RR format, OPT, TCP framing, matcher and classifier contracts, caps table); `lab/topo/dnslab.sh`, zone files, `lab/dns/root.hints`, `lab/svc.sh`; approval request for nsd, unbound, dig | Which names and addresses must a resolver know before it can resolve anything, and where do they come from? | spec approved; `dig +norecurse` against `10.0.5.1`, `.2`, `.3` shows the three-step delegation; `make phase0` green |
| M10 | Name codec | `nt_dns_name_decode` (compression, caps, escaping), encode, case-insensitive compare, label-boundary suffix test | golden vectors from scapy/dig; loop, forward, self and into-header pointer cases; escape tests | In the answer to `www.example.test`, the owner name is two bytes. Which, and what do they point at? | unit tests green incl. every pointer case; ASan/UBSan clean |
| M11 | Message codec and sniffer view | header, question, RR and RDATA decoders, OPT, `nt_build_dns_query`, `sniff --dns` printer | `py/gen_dns_fixtures.py` → `fixtures/dns-good.pcap`, `dns-malformed.pcap`; `scripts/tshark-dns.sh` | Which flag bits does `dig` set in its query (use `+qr`), and what does AD mean in a query? | `sniff --dns` equals tshark on `dns-good.pcap`; every malformed frame returns its expected status |
| M12 | Stub resolver (UDP) | `dnsq`: query, per-query socket, `getrandom` id, matcher use, validation, retries, ignore counters | `py/dnsd.py` hostile responder, `scripts/dnsq-vs-dig.sh` | How many bits stop an off-path forger, and which of them does the kernel give you for free? | answers equal `dig` for the lab zones; forged and mismatched replies ignored and counted; 20-query capture shows distinct ids and source ports |
| M13 | EDNS0, truncation, TCP | OPT handling, `--edns`, `--no-edns`, TC handling, TCP framing under a deadline | 3000-byte TXT, MTU scenario, slow-drip TCP responder | A 3000-byte TXT answer with EDNS 4096 over a 1500-byte MTU: how many IP packets carry it, and what does your sniffer show for the second one? | UDP → TC → TCP sequence captured and explained; fragmented UDP response flagged as a fragment in the sniffer and received whole by the resolver |
| M14 | Iterative walk | classifier logic, referral following, CNAME chains, caps, `--iter --trace`; optional glueless NS with depth cap 2 | `scripts/walk-vs-dig.sh` (manual `+norecurse` steps), hostile referral modes | How many queries does a cold walk to `www.example.test` take, and which response carries glue? | trace equals the dig manual walk; loops, lame servers and out-of-bailiwick data end in a named error, never a hang |
| M15 | Spoofing lab (lab only) | `--weak` mode; optional 0x20 case randomization | `py/dns_spoof.py` (off-path guessing and on-path racing, at most 30 s), hub or `tc mirred` setup for `evil` | Can an on-path forger who sees your query beat id and port randomization? What would stop it? | `--weak` poisoned within the bounded run; strong mode survives off-path; on-path wins; results and defences written down |
| M16 | Hardening | fixes only | `fuzz_dns_name.c`, `fuzz_dns_msg.c`, `fuzz_dns_classify.c`, corpus script, failure-injection script (server down, lame, fragments black-holed) | Which breaks first under fuzzing: name expansion, RDATA decode, or the classifier? | 5 minutes per target clean; all hostile modes rejected; failure runs finish within the 10 s deadline |
| M17 | Write-up | `docs/phase5.md` | review | none | see Definition of done |

Optional stretches (only if time remains inside the box): glueless NS resolution, 0x20 encoding, `ncx` and `traceroute`
reverse lookups through your own resolver.

---

## Sub-phase 6: DHCP (M18-M23)

**GOAL:** a DHCP codec and a DORA client that gets a lease from `dnsmasq` over a raw socket, validates everything it
receives, and survives a rogue server and a starved pool.
**OUT OF SCOPE:** renewal, rebinding, T1/T2 timers, INFORM, DHCPv6, relay (giaddr is decoded only), lease database,
PXE/boot options (siaddr and file are decoded, not used), option 82, applying the lease from C.
Optional stretches: ARP probe then DECLINE on conflict (reuse the Phase 3 probe), and RELEASE.

**Lab (`dhcp1`):** `c1` (no address), `dhcpd` 10.0.6.1/24 (dnsmasq, pool 10.0.6.100-150, short lease), `rogue` 10.0.6.66
(second dnsmasq with a different router and DNS, started on demand), one bridge. A second config uses a
10-address pool for the starvation run.

| # | Deliverable | Owner implements | Agent provides | Predict before you run | Sign-off test |
|---|---|---|---|---|---|
| M18 | Spec and scaffolding | nothing | one-page spec (BOOTP header offsets, cookie, option and message-type tables, INIT→BOUND diagram, matcher contracts, timers), `lab/topo/dhcp1.sh`, dnsmasq configs, `lab/apply-lease.sh` skeleton with hostile-lease tests, `py/udp68.py` (UDP-socket receiver) | Which source and destination IPv4 and Ethernet addresses does a DISCOVER carry, and why can't the server ARP for the client? | spec approved; an oracle client gets a lease from `dhcpd`; `make phase0` green |
| M19 | DHCP codec | `nt_dhcp_decode`, builders, `nt_build_eth_ipv4_udp`, matchers, `sniff --dhcp` printer | `py/gen_dhcp_fixtures.py` → `dhcp-good.pcap`, `dhcp-malformed.pcap`; `scripts/tshark-dhcp.sh` | What sits at byte offset 236 of a DHCP message? | unit tests and malformed frames all return expected statuses; `sniff --dhcp` equals tshark |
| M20 | DISCOVER and OFFER | raw socket, DISCOVER send, OFFER receive and validation, backoff, offer window | hostile server script, broadcast-flag experiment | Does the server send the OFFER unicast or broadcast, and what changes with the broadcast flag? | OFFER matches the dnsmasq log; `py/udp68.py` receives it only with the flag set; hostile OFFERs ignored and counted |
| M21 | REQUEST, ACK/NAK, lease | REQUEST, ACK/NAK validation, lease sanity checks, escaped output | NAK scenario (request a wrong IP), finished `lab/apply-lease.sh` | What are the IPv4 source and destination of the REQUEST, and why does it carry the server identifier? | `dhcpc` plus `apply-lease.sh` yields a working address (ping across `dhcp1` passes); lease equals dnsmasq's lease file; NAK handled |
| M22 | Rogue, starvation, defences (lab only) | `--trust-server`, multi-offer warning | rogue config, starvation script (at most 32 DORAs), bridge-family `nft` drafts (checked with `nft -c`), tshark detection one-liners | With two servers answering, which OFFER does your client take, and what decides it? With a 10-address pool and 12 distinct chaddrs, what does the 11th client see? | rogue lease demonstrated and detected; `--trust-server` defeats it; starvation reproduced; each defence tested and documented |
| M23 | Hardening and write-up | fixes, `docs/phase6.md` | `fuzz_dhcp.c`, `fuzz_dhcp_match.c`, review | none | see Definition of done |

---

## Hostile fixtures (the agent writes the generators; the owner's code must survive all of them)

**Sockets:** peer that resets mid-transfer; peer that never reads; peer that sends one byte per second; peer that
connects and idles; peer that half-closes then sends more; 1000 simultaneous connects; connect storm against a
backlog of 1; UDP datagram larger than the receive buffer; datagram from an unexpected source.

**DNS:** truncated header; counts claiming 65535 records; pointer to itself, forward, into the header, chains that
bounce between two offsets; label of 64 bytes; reserved label types; name longer than 255; RDLENGTH beyond the message
or too short for its name; A with RDLENGTH 3; TXT strings overrunning RDATA; two questions; two OPTs; OPT with a
non-root owner; QR=0 sent as a response; wrong id, wrong question, wrong case (when exact case is required);
NXDOMAIN carrying answers; CNAME loop, self-CNAME, chain of 20; referral back to the parent; referral to an
unrelated zone; NS owner `ample.test` for `example.test` (string-suffix trap); glue for a name not in the NS set;
answer for another name; names with newlines, ANSI escapes, NULs and dots in labels; 64 KiB TCP response; TCP length
prefix 0, prefix larger than the data, one byte per second; 100 identical responses; reply from the wrong
address or port; reply after the deadline.

**DHCP:** under 240 bytes; wrong cookie; option length past the end; no END; missing option 53; option 53 twice or with
length 2; wrong xid; wrong chaddr; op=1 where a reply is expected; `hlen` above 16 or not 6 for `htype` 1; option 54
with length 3; routers with length 5; yiaddr 0; lease time 0; option 52 overload; garbage in sname/file; a NAK with
control characters in option 56; hostname with NUL or newline; PAD runs filling the packet; options after END; UDP
checksum wrong; UDP checksum zero (must be accepted); wrong UDP ports.

---

## Gotchas cheat sheet (the agent raises each at the milestone it belongs to, not before)

**Sockets**
- `connect()` succeeds as soon as the kernel finishes the handshake, even if the server never calls `accept()`.
- The accept queue holds backlog+1 entries, capped by `net.core.somaxconn`. In `ss -ltn`, Recv-Q is the current queue
  length and Send-Q the limit. SYN queue and accept queue are different; `nstat` shows `ListenOverflows` and `ListenDrops`.
- Only the side that closes first enters TIME_WAIT (60 s fixed on Linux). `SO_REUSEADDR` lets a listener bind
  through it, but never lets two listeners share a port. `SO_REUSEPORT` does, and lets same-user processes steal connections.
- `close()` with unread received data sends RST instead of FIN, and the peer can lose data it had not read yet.
- A level-triggered listener you cannot `accept()` from (`EMFILE`) keeps firing and spins the loop.
- Nagle plus delayed ACK stalls small writes for about 40 ms on Linux. `TCP_CORK`/`MSG_MORE` are the batching tools.
- Nonblocking `connect()` returns `EINPROGRESS`; completion is `EPOLLOUT` followed by `SO_ERROR`.
- Edge-triggered epoll needs a drain-until-`EAGAIN` loop on every readable event, including `accept`.
- `SO_RCVBUF`/`SO_SNDBUF` are doubled by the kernel. `tcp_tw_reuse` defaults differ by kernel version: check yours.
- Loopback has a 64 KiB MTU and different segmentation; observe on veth with offloads off.
- Connected UDP sockets receive ICMP errors as `ECONNREFUSED` on a later call; unconnected ones silently see nothing.
- Dual-stack: `IPV6_V6ONLY` defaults to 0 on Linux, so a v6 listener also accepts IPv4-mapped connections.

**DNS**
- Pointer offsets count from the start of the DNS message. Over TCP that is after the 2-byte length prefix, a classic off-by-two.
- Names are case-insensitive but case-preserving. Labels may hold any byte, including NUL and `.`.
- Without EDNS, UDP answers are capped at 512 bytes. 1232 is the recommended EDNS size, chosen to avoid IP fragmentation
  (and the fragment-based poisoning that comes with it).
- RCODE spans two places: the header's 4 bits and the OPT record's extended 8 bits.
- NXDOMAIN means the name does not exist; NODATA means it exists without that type (NOERROR, empty answer, SOA in authority).
- A wildcard answer carries the qname as owner, not `*`.
- Referral versus answer is decided by section contents, not AA. Glue is trusted only for NS names from the same message.
- `dig` sets RD and AD and adds EDNS by default; compare against it with `+noedns`/`+norecurse` as needed.
- `unbound` minimizes the qname toward the root and `tld` servers; your walk sends the full name. The difference is visible in captures.
- Entropy off-path is about 16 bits (id) plus about 14 bits (the default ephemeral range of roughly 28000 ports). It does nothing against an
  on-path attacker, who sees both.
- Responses larger than the path MTU arrive as IP fragments; the second fragment has no UDP header.
- Packets arriving after the first valid answer are not errors, and a forged packet arriving first must not end the query.

**DHCP**
- Before configuration the client sends from `0.0.0.0` to `255.255.255.255` with Ethernet broadcast. A server that unicasts
  the OFFER to yiaddr is answering an address the client does not own yet, so an ordinary UDP socket never sees it. That
  is why DHCP clients use raw sockets, and why the broadcast flag (`0x8000`) exists.
- dnsmasq pings the candidate address before offering, which can delay the OFFER by up to about 3 s unless `--no-ping`
  is set (measure it). Retransmit timers shorter than that produce duplicate DISCOVERs.
- dnsmasq inserts a neighbor entry from chaddr to unicast its reply; check `ip neigh` on the server.
- Servers key leases on chaddr, not on the Ethernet source address.
- A REQUEST in SELECTING state is broadcast so every server learns whose offer was accepted (option 54).
- The `file`/`sname` fields can carry options (option 52) and the 300-byte BOOTP minimum still applies to what you send.
- DHCP has no authentication: whoever answers first wins, and option values are attacker-controlled. Real CVEs came from
  passing them to shell scripts.
- `AF_PACKET` delivers every IPv4 packet in the namespace: filter in user space (BPF arrives in Phase 11).

---

## Definition of done

**Sub-phase 4**
- [ ] M0-M8 signed off; `make BUILD=asan test` and `make san-test` green, zero warnings
- [ ] `ncx` transfers 64 MiB both ways with matching checksums; EOF and half-close cases match the spec
- [ ] `echod` survives the slow-client suite and flood script with flat memory and a baseline fd count
- [ ] each experiment has tool output, `ss`/`nstat` output and a capture that agree
- [ ] `docs/phase4.md` with at least two break-and-debug write-ups and a security note (including at-capacity policy and the `-e` omission)
- [ ] time within ~1 week; overruns noted with the cause

**Sub-phase 5**
- [ ] M9-M17 signed off; sanitizers clean; `make fuzz` 5 minutes per target with no findings, corpus saved under `fuzz/corpus/`
- [ ] `sniff --dns` equals tshark on `dns-good.pcap`; every `dns-malformed.pcap` frame rejected with its expected status
- [ ] `dnsq` equals `dig` for every lab zone entry; iterative trace equals the manual `dig +norecurse` walk
- [ ] UDP, EDNS, TC and TCP fallback each captured and explained; fragmentation observed
- [ ] spoof-race results documented (off-path, on-path, `--weak`) with the defences that apply
- [ ] every hostile responder mode ends in a named error within the 10 s deadline
- [ ] `docs/phase5.md`: break-and-debug (including the fragments-dropped scenario), security note (poisoning, tunneling), later-list
- [ ] time within ~2 weeks

**Sub-phase 6**
- [ ] M18-M23 signed off; sanitizers clean; `make fuzz` 5 minutes per target with no findings
- [ ] `dhcpc` plus `apply-lease.sh` configures `c1`; lease matches dnsmasq's file; the NAK case is handled
- [ ] `sniff --dhcp` equals tshark on `dhcp-good.pcap`; every malformed frame rejected with its expected status
- [ ] broadcast-flag, ping-check delay and chaddr experiments captured and explained
- [ ] rogue server demonstrated, detected, and defeated with `--trust-server`; starvation reproduced; each defence tested
- [ ] hostile lease files refused by `apply-lease.sh`
- [ ] capabilities dropped after socket open, verified with `grep Cap /proc/<pid>/status`
- [ ] `docs/phase6.md`: break-and-debug, security note (no authentication, option injection), later-list
- [ ] time within ~1 week
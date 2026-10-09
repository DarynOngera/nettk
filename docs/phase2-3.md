# Phase 2+3: ping, traceroute, ARP and NDP

Spec (M0) and write-up for phases 2 and 3 combined. Source: `docs/phase2-3-prompt.md`.
Mode: IMPLEMENT, milestone-gated. Phase 1 decoders in `src/lib/` are reused unchanged; a Phase 1
bug is fixed with a failing regression test first.

Status: complete through M13. Verified on this host: `sudo lab/check.sh` on `basic` = 13/13 and
`sudo lab/scenarios-traceroute.sh` on `line4` = 3/3. The `arp`/`ndp`/`spoof` scenario scripts still
need a root run (`sudo lab/scenarios-arp.sh`, `-ndp.sh`, `-spoof.sh`).

## 1. Goal

Active tools that match the system oracles on the lab: `ping` and `traceroute` (IPv4/IPv6) that
validate every reply against what was actually sent, and an ARP resolver/scanner/monitor plus a
lab-only spoofer and NDP resolver. Everything sends only inside `nt-*` namespaces.

## 2. Safety: the guard

Every sending tool calls `nt_guard_*` before the first send. The guard refuses unless all hold:

| Condition | Check |
|---|---|
| running under the lab | `NT_LAB == "1"` (set by `lab/ex`) |
| IPv4 target in range | `10.0.0.0/16` |
| IPv6 target in range | `fd00::/8` (ULA) or `2001:db8::/32` (doc) |
| ARP/NDP interface is virtual | NIC driver is `veth` (`ETHTOOL_GDRVINFO`) |

The guard is a **seatbelt against typos, not a security boundary**: a determined caller can unset
`NT_LAB`. It exists so a mistyped address cannot reach a real network by accident.

## 3. Wire formats (offsets in bytes)

**ICMPv4 echo (RFC 792)** — checksum covers the ICMP message only, never the IP header.

| off | size | field | notes |
|---|---|---|---|
| 0 | 1 | type | 8 request, 0 reply |
| 1 | 1 | code | 0 |
| 2 | 2 | checksum | ones-complement |
| 4 | 2 | identifier | ours |
| 6 | 2 | sequence | ours |
| 8 | n | data | echoed verbatim; validate against what we sent |

**ICMPv4 error (RFC 792)** — destination unreachable (3), time exceeded (11), parameter problem (12).
Quote is the original IPv4 header plus at least 8 bytes of its payload (RFC 792); RFC 1812 routers
may quote more.

| off | size | field | notes |
|---|---|---|---|
| 0 | 1 | type | 3 / 11 / 12 |
| 1 | 1 | code | 3: net/host/proto/port/frag-needed; 11: TTL/assembly |
| 2 | 2 | checksum | |
| 4 | 4 | rest | 3/11: unused or next-hop MTU (code 4); 12: pointer |
| 8 | m | quoted packet | quoted IPv4 header (validate IHL, proto) + 8+ bytes |

**ARP for IPv4 over Ethernet (RFC 826), 28 bytes** — as Phase 1 (`nt_arp`): htype 0/2=1, ptype 2/2
=0x0800, hlen 4/1=6, plen 5/1=4, op 6/2 (1 req, 2 reply), sha 8/6, spa 14/4, tha 18/6, tpa 24/4.
Frames are padded to 60 bytes (AF_PACKET does not pad).

**ICMPv6 NS / NA (RFC 4861 s4.3/4.4)** — checksum uses the IPv6 pseudo-header (kernel fills it on
raw ICMPv6 sockets).

| off | size | NS (135) | NA (136) |
|---|---|---|---|
| 0 | 1 | type 135 | type 136 |
| 1 | 1 | code 0 | code 0 |
| 2 | 2 | checksum | checksum |
| 4 | 4 | reserved | R/S/O flags + reserved |
| 8 | 16 | target address | target address |
| 24 | n | options (SLLADDR) | options (TLLADDR) |

NS is sent to the solicited-node multicast `ff02::1:ffXX:XXXX` with hop limit 255; a NA is accepted
only if hop limit is exactly 255 (s7.1) — no off-link attacker can forge that.

## 4. Socket modes

| Mode | socket | recv contains IP hdr | checksum | id | needs |
|---|---|---|---|---|---|
| ping raw v4 | `AF_INET, SOCK_RAW, IPPROTO_ICMP` | yes | we compute | we choose | CAP_NET_RAW |
| ping dgram v4 | `AF_INET, SOCK_DGRAM, IPPROTO_ICMP` | no | kernel | kernel rewrites it | `ping_group_range` in ns |
| ping v6 | `AF_INET6, SOCK_RAW, IPPROTO_ICMPV6` | no | kernel (pseudo-hdr) | we choose | CAP_NET_RAW |
| traceroute UDP | `AF_INET, SOCK_DGRAM` + raw ICMP recv | n/a | kernel | n/a | CAP_NET_RAW for recv |
| ARP | `AF_PACKET, SOCK_RAW, ETH_P_ARP` | n/a (L2) | n/a | n/a | CAP_NET_RAW |

`ICMP_FILTER` / `ICMP6_FILTER` narrow the raw socket to echo-reply, dest-unreachable, time-exceeded;
user space still validates every field.

## 5. Builder API (`src/lib/`, pure, no I/O)

```c
/* ICMPv4 echo; computes the ICMP-only checksum */
nt_status nt_build_icmp_echo(uint8_t *out, size_t cap, size_t *outlen,
                             uint8_t type, uint16_t id, uint16_t seq,
                             const uint8_t *data, size_t datalen);

typedef struct {
    uint8_t  eth_src[6], eth_dst[6]; /* Ethernet addrs (eth_dst = broadcast for a request) */
    uint16_t op;                     /* 1 request, 2 reply */
    uint8_t  sha[6], spa[4];         /* sender hardware/protocol */
    uint8_t  tha[6], tpa[4];         /* target hardware (zero for a request) / protocol */
} nt_arp_in;
nt_status nt_build_arp_frame(uint8_t *out, size_t cap, size_t *outlen, const nt_arp_in *in);

/* NS with source link-layer option; computes the ICMPv6 checksum over the pseudo-header */
nt_status nt_build_icmp6_ns(uint8_t *out, size_t cap, size_t *outlen,
                            const uint8_t src[16], const uint8_t dst[16],
                            const uint8_t target[16], const uint8_t src_ll[6]);
```

Contract: check `cap` before every write; compute checksums with the Phase 1 `nt_csum_*` helpers
(never duplicate); return `NT_ERR_TRUNCATED` when `cap` is too small.

## 6. Matcher contract (`src/lib/`, no sockets, fuzzable)

```c
typedef enum { NT_MATCH, NT_NO_MATCH, NT_INVALID } nt_match;
```

- `nt_match_icmp_echo_reply(const nt_icmp *r, const nt_ipv4 *ip, uint16_t id, uint16_t seq, uint32_t src)`
  — `MATCH` only if type/code is 0/0, checksum valid, id/seq equal ours, source equals the target.
- `nt_match_icmp6_echo_reply(...)` — same for ICMPv6.
- `nt_match_icmp_error(const nt_icmp *err, const nt_probe *sent, nt_quoted *q)` — parse the quote
  (bounds-checked) and match protocol, source/dest address, and the UDP/ICMP ports of an outstanding
  probe; `INVALID` for a malformed quote, `NO_MATCH` for a well-formed quote of another flow.
- `nt_match_arp_reply(const nt_arp *r, const nt_arp_in *req, const uint8_t eth_src[6])`.
- `nt_match_na(const nt_icmp *na, const uint8_t target[16], int hop_limit)` — require hop limit 255.

`NO_MATCH` is never an error; only `INVALID` (malformed input) is counted separately.

## 7. Topology `line4` (M0 scaffolding)

```
h1 10.0.1.2/24 -- r1 10.0.1.1/24
                  r1 10.0.9.1/30 -- r2 10.0.9.2/30
                                     r2 10.0.2.1/24 -- h2 10.0.2.2/24
```
MACs `02:00:00:00:<net>:<host>`; both routers forward IPv4. IPv6 (`fd00:1::/64`, `fd00:2::/64`)
is added to `basic` at M4. Guard range `10.0.0.0/16` covers every address here.

## 8. Out of scope

Ping flood, IP options (record route), TCP traceroute (Phase 7), reverse DNS (Phase 5), Paris/ECMP
traceroute, full PMTU discovery (Phase 8), proxy ARP, DAD and RA, DHCP, and anything outside `nt-*`.

## 9. Milestone status

| M | Deliverable | Status |
|---|---|---|
| M0 | spec + scaffolding (`line4`, `NT_LAB`, `src/common/`, Makefile) | done (basic 13/13) |
| M1 | builders + golden vectors | done |
| M2 | ping v4 raw | done |
| M3 | ping extras | done |
| M4 | ping v6 | done (basic IPv6 ping green) |
| M5 | traceroute UDP | done (oracle match green) |
| M6 | traceroute ICMP + codes | done (ICMP oracle + `!N`/`!X`/`!F` green) |
| M7 | ARP resolve/probe | done (arp oracle green; hostile scenario pending root) |
| M8 | ARP scan | done (bridge3 scan oracle pending root) |
| M9 | NDP resolve | done (ndp oracle green; hostile scenario pending root) |
| M10 | ARP monitor | done (fixture check green) |
| M11 | spoof and defend | done (spoof scenario pending root) |
| M12 | hardening | done |
| M13 | lab validation + write-up | done (basic 13/13, traceroute 3/3) |

## 10. Write-up

Oracle results are the evidence rows below ("owner to run" where the check needs root). The
break-and-debug experiment is `lab/scenarios-spoof.sh`: predict that poisoning succeeds and is
caught by `arpmon`, then that a `nud permanent` entry ignores it.

### Security note

Attack surface, from most to least exposed:

| Surface | Threat | Hardening |
|---|---|---|
| Packet parsers (`src/lib/`) | adversarial frames over the wire / pcaps | explicit length checks before every read, no struct overlay, `malformed.pcap` rejected; `fuzz_decode` 45.9M runs + `fuzz_match` 16.9M runs clean under ASan/UBSan |
| Live capture socket | captured payloads treated as data, never instructions | decoders return values only; no `system`/`exec`/format-string from capture |
| Raw sends (`arpspoof`, `arp scan`, `ndp`, `ping`, `traceroute`) | accidentally attacking the host network | `nt_guard_*`: require `NT_LAB=1`, target inside `10.0.0.0/16` / `fd00::/8`, iface driver must be `veth`; `arpspoof` makes no changes and restores the true MAC on exit |
| Privileges | broad root after a raw socket is opened | `nt_live_open` drops to the invoking uid and keeps only `CAP_NET_RAW`; `caps_are_minimal` reads `/proc/self/status` and fails the open if any other capability remains |

What remains (by design, out of scope):

- The guard is a **seatbelt against typos, not a security boundary** (see §6). Code that unsets
  `NT_LAB`, and has `CAP_NET_RAW` inside a namespace, can still send. Mitigations are kernel-side
  and outside this phase: static/`permanent` neighbour entries, `arp_ignore`/`arp_accept`, and
  switch DAI/port security.
- `arpspoof` requested no L2 filtering; on a shared segment it is only safe because the guard keeps
  it on lab veths.
- No IPv6 ND spoofing tool is provided (observe/`ndp` resolve only).

## 11. Evidence (M0-M13)

| Check | Command | Result |
|---|---|---|
| unit suite | `make BUILD=asan test` | 15 binaries pass; `test_build` 49/49, `test_guard` 26/26, `test_clock` 9/9 |
| M1 golden vectors | `make golden && make BUILD=asan test` | builds match scapy byte-for-byte (`fixtures/golden/*.hex`) |
| no warnings | `make BUILD=asan all`, `make BUILD=release all` | clean, zero warnings |
| sniffer still works after move | `bin/sniff -r fixtures/basic.pcap --tsv` | 14 rows, same as Phase 1 |
| basic lab (all tools) | `sudo lab/up.sh basic --force && sudo lab/check.sh` | `passed=13 failed=0 skipped=0` (IPv4/IPv6 ping, traceroute UDP+ICMP, arp, ndp, capture, offloads, caps) |
| line4 scenarios | `sudo lab/up.sh line4 --force && sudo lab/scenarios-traceroute.sh` | `passed=3 failed=0` (`!N`, `!X`, `!F mtu=1400`) |
| M2/M3 matchers | `make BUILD=asan test` | `test_match` 29/29 (`nt_match_icmp_echo_reply`, `nt_match_icmp6_echo_reply`, `nt_icmp_quote_parse`) |
| M4 icmpv6 echo | `make golden && make BUILD=asan test` | `test_build` 58/58; `icmp6_echo.hex` byte-identical to scapy |
| M5 traceroute UDP oracle | `lab/check.sh` basic | PASS: hop list matches `traceroute -n -U -q1` |
| M6 traceroute modes | `lab/check.sh` basic | PASS: `-I` hop list matches `traceroute -n -I` |
| M6 error annotations | `sudo lab/scenarios-traceroute.sh` (line4) | `passed=3 failed=0`: `!N`, `!X`, `!F mtu=1400` |
| M7 arp hostile | `sudo lab/scenarios-arp.sh` | owner to run (root); honest accepted, 3 hostile rejected, dup counted |
| M7 arp oracle | `lab/check.sh` basic | PASS: MAC matches `arping -I` (read from `$5`) |
| M8 arp scan oracle | `lab/check.sh` bridge3 | owner to run (root); compares to `nmap -sn -PR -n 10.0.0.0/24` |
| M9 ndp oracle | `lab/check.sh` basic | PASS: MAC matches `ip -6 neigh` for `fd00:1::1` |
| M9 ndp hostile | `sudo lab/scenarios-ndp.sh` | owner to run (root); hop64 / wrong-target / bad-checksum rejected |
| M10 arpmon fixtures | `make arpmon-check` | all 6 rules fire on `arp-spoof.pcap`; RSS 12 MiB on 20k-packet flood |
| M11 spoof/defend | `sudo lab/scenarios-spoof.sh` | owner to run (root); poison, arpmon alert, restore-on-exit, static-neigh defence |
| M12 fuzzers | `make fuzz && make fuzz-seeds`, then run each harness | `fuzz_decode` 45.9M runs/301 s and `fuzz_match` 16.9M runs/121 s, no crash/finding |
| M12 capability drop | `make BUILD=asan all` then live capture in lab | after `nt_live_open`, `CapEff` is exactly `CAP_NET_RAW` (0x2000) or the open fails |
| M13 smoke | `sudo lab/up.sh basic --force && sudo lab/check.sh` | `passed=13 failed=0 skipped=0` |

Shared I/O moved from `src/sniff/` to `src/common/` (`pcap.{c,h}`, `live.{c,h}`); tools now link
`libntcommon.a`, and the Makefile excludes `src/common/` from discovery.

## 12. Lab-run fixes (M13)

Bringing `lab/check.sh` and `lab/scenarios-traceroute.sh` to green surfaced nine defects. All were
fixed at the source, not worked around:

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | traceroute UDP, arp, ndp oracle mismatch (exit 2) | callers pass attached option values (`-W1`, `-c1`, `-m5`); parsers accepted only separated `-W 1` | `src/common/opts.h` `nt_opt_value()` accepts both; wired into `ping`, `traceroute`, `arp`, `ndp`, `arpspoof` |
| 2 | arp MAC mismatch | `lab/check.sh` read `$4` (the IP) from `Unicast reply from <ip> [<mac>]` | read `$5` |
| 3 | first hop `*` in traceroute | `-W1` is 1 ms (our `-W` is milliseconds), too short for the first ARP/NDP resolution | `-W1000` at the call sites |
| 4 | `traceroute -I` printed `sendto: Invalid argument` | ICMP mode passed a 4-byte `in_addr` cast to `struct sockaddr *` | build a `sockaddr_in` as UDP mode does |
| 5 | `traceroute -I` saw no hops (after #4) | `nt_icmp_quote_parse` read the quoted echo id/seq at offsets 0/2 (type/code) instead of 4/6 | read offsets 4 and 6; `test_match` updated |
| 6 | IPv6 ping across the router failed on a cold lab | `nodad` only covers our global addresses; the auto-generated link-local still runs DAD (~1 s), so ND cannot send | set `accept_dad=0` on each lab interface before link-up (`lab/lib.sh`) |
| 7 | `scenarios-traceroute.sh` `!X` never fired | `fwd` is a reserved nftables keyword, so the chain was rejected | rename the chain to `ntfwd` |
| 8 | `!F` failed on a rerun with `sendto: Message too long` | a previous run cached the 1400 PMTU exception on h1, so the first DF send failed locally | flush h1's route cache before the DF probe (and in `restore`) |
| 9 | `ndp` oracle match flaked on a cold lab | the oracle read the first neighbour on the link (ordering-dependent) and one NS raced the router's readiness | scope the oracle to the target address; let the tool retry (`-c3`) |

Re-verify (cold):

```bash
make BUILD=asan all
sudo lab/up.sh basic --force && sudo lab/check.sh                  # passed=13 failed=0
sudo lab/up.sh line4 --force && sudo lab/scenarios-traceroute.sh   # passed=3 failed=0
```

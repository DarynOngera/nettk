# Phase 6: DHCP — codec, DORA client, rogue server and starvation (M18–M23)

Date: 2026-10-13 | Time-box: ~1 week | Status: **M18–M19 done and verified; M20–M22 code
written, lab gates awaiting root (see "To run as root" below); M23 fuzz + write-up done**

## Goal (one sentence)

Understand DHCP end to end — the BOOTP fixed header, option TLV stream, the DORA
state machine and its timers, and why a client needs a raw socket and a
broadcast flag — by writing a from-scratch C codec, a `dhcpc` DORA client over
`AF_PACKET`, a `sniff --dhcp` printer, and a lease-applying script, all gated
against `dnsmasq`, `dhclient`/`udhcpc`, tshark and `py/udp68.py` inside the lab.

## Safety envelope for this phase (adds to AGENTS.md rules)

- Every DHCP send stays inside the `nt-*` dhcp1 namespace and is refused unless
  `NT_LAB=1` (the guard). The rogue server and the starvation run are bounded
  (≤ 32 DORAs, ≤ 30 s). Nothing touches the host or a real network.
- `dhcpc` opens the raw socket, drops to the invoking user, and keeps only
  `CAP_NET_RAW` (rule 3 of the phase prompt). No libc resolver, no `resolv.conf`.
- `lab/apply-lease.sh` never pipes option values to a shell. It validates every
  field and passes addresses as `ip` arguments only (CVE-class hardening; see
  the security note).

## Wire format

DHCP is BOOTP plus a magic cookie and a TLV option stream (RFC 2131 §2,
RFC 2132). The codec consumes the **UDP payload**, not the IP packet.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 1 | `op` | 1 = BOOTREQUEST, 2 = BOOTREPLY |
| 1 | 1 | `htype` | 1 = Ethernet |
| 2 | 1 | `hlen` | 6 for Ethernet; never > 16 |
| 3 | 1 | `hops` | relay count |
| 4 | 4 | `xid` | transaction id, chosen by the client |
| 8 | 2 | `secs` | seconds since the client began |
| 10 | 2 | `flags` | bit 15 = broadcast desired (`0x8000`) |
| 12 | 4 | `ciaddr` | client IP (only when it already has one) |
| 16 | 4 | `yiaddr` | "your" IP, the address being offered |
| 20 | 4 | `siaddr` | next-server (boot server) |
| 24 | 4 | `giaddr` | relay agent gateway |
| 28 | 16 | `chaddr` | client hardware address (`hlen` significant bytes) |
| 44 | 64 | `sname` | server name (or options if option 52 says so) |
| 108 | 128 | `file` | boot file (or options if option 52 says so) |
| 236 | 4 | magic cookie | `63 82 53 63` |
| 240 | var | options | TLV, terminated by byte 255 (END) |

Everything is big-endian. Minimum message is 240 bytes (header + cookie); a
client must send at least 300 bytes of BOOTP payload (RFC 2131 §2), so the
builder zero-pads after END to 300.

### Option TLV

`code` (1) | `len` (1) | `data` (`len`). Code 0 (PAD) is a single byte and is
skipped; code 255 (END) stops the walk. A missing END is malformed.

| code | name | expected length | our treatment |
|---|---|---|---|
| 1 | subnet mask | 4 | decode |
| 3 | router | non-zero multiple of 4 | decode (first 4 kept) |
| 6 | DNS | non-zero multiple of 4 | decode (first 4 kept) |
| 12 | hostname | any | escaped free text, truncated to 64 |
| 15 | domain name | any | escaped free text |
| 50 | requested IP | 4 | decode |
| 51 | lease time | 4 | decode |
| 52 | option overload | 1 | **UNSUPPORTED** (sname/file reuse out of scope) |
| 53 | message type | 1, value 1–8 | decode |
| 54 | server identifier | 4 | decode |
| 55 | parameter request list | any | walked, ignored |
| 56 | message | any | escaped free text |
| 57 | max message size | 2 | walked, ignored |
| 58 | renewal T1 | 4 | decode |
| 59 | rebinding T2 | 4 | decode |
| 61 | client identifier | any | walked, ignored |
| 0 / 255 | PAD / END | 1 | control |

A repeated option is `MALFORMED`; long-option concatenation (RFC 3396) is
therefore out of scope. Unknown options are length-checked, walked and ignored.

### Message types (option 53)

| value | name | who sends it |
|---|---|---|
| 1 | DISCOVER | client broadcast, "anyone out there?" |
| 2 | OFFER | server, proposed `yiaddr` |
| 3 | REQUEST | client; either SELECTING (with option 54) or REBINDING |
| 4 | DECLINE | client, address already in use |
| 5 | ACK | server, lease confirmed |
| 6 | NAK | server, request refused |
| 7 | RELEASE | client, giving the lease back |
| 8 | INFORM | client, already has an address, wants parameters |

### DORA (INIT → BOUND)

```
client (0.0.0.0:68)                    server (10.0.6.1:67)
    |  DISCOVER  (bcast eth+ip, xid=X)      |
    |-------------------------------------->|
    |  OFFER     (yiaddr, server id)        |   <- bcast unless it can unicast
    |<--------------------------------------|
    |  REQUEST   (bcast, option 54, option 50)
    |-------------------------------------->|
    |  ACK       (lease, T1, T2, options)   |
    |<--------------------------------------|
    BOUND      renew at T1 (unicast), rebind at T2 (bcast), expire at lease
```

INIT also sends a REQUEST *without* option 54 to confirm a previously known
address (INIT-REBOOT), and a RELEASE frees the lease.

## Caps (hard limits, enforced even in hostile fixtures)

| limit | value | why |
|---|---|---|
| short message | < 240 bytes | `TRUNCATED` |
| `hlen` | > 16 = `MALFORMED`; `htype 1` needs 6 | RFC 2131 §2 |
| option length | must fit the buffer | rule 35 |
| repeated option | `MALFORMED` | disables RFC 3396 ambiguity |
| option 52 | `UNSUPPORTED` | sname/file reuse out of scope |
| free text | escaped, 64 bytes | no terminal control characters |
| DISCOVER retries | 4, backoff 1,2,4,8 s (×secs jitter) | prompt rule 7 |
| offer window | 3 s | take the first valid OFFER |
| whole exchange | 30 s deadline | prompt rule 7 |
| starvation | ≤ 32 DORAs in one run | bounded |

## Contracts

### API (`src/lib/dhcp.h`, implemented M19)
```
nt_dhcp_decode(const uint8_t *buf, size_t len, nt_dhcp *out)       -> nt_status
nt_dhcp_build(const nt_dhcp_out *o, uint8_t *out, size_t cap,
              size_t *outlen)                                       -> nt_status
nt_build_eth_ipv4_udp(out, cap, &outlen, eth_src, eth_dst,
                      sip, dip, sport, dport, payload, plen)        -> nt_status
nt_dhcp_match_offer(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6]) -> nt_match
nt_dhcp_match_ack(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6],
                  uint32_t requested_ip)                            -> nt_match
nt_dhcp_match_nak(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6])   -> nt_match
nt_dhcp_msg_type_str(uint8_t), nt_dhcp_op_str(uint8_t)
```
All parsers take `(buf, len)`, validate before every read, and return error
codes; the library does no I/O and no allocation.

### Matchers (rule 38)
`INVALID` = cannot be trusted; `NO_MATCH` = well-formed but not ours (never an
error); `MATCH` = accepted.

| matcher | requires |
|---|---|
| offer | `op=2`, xid, chaddr, type OFFER, server id present, `yiaddr != 0` |
| ack | offer checks plus type ACK and `yiaddr == requested_ip` |
| nak | `op=2`, xid, chaddr, type NAK |

### Client states (`src/dhcpc`)
`INIT → SELECTING → REQUESTING → BOUND`; `NAK` → back to `INIT`. Timers from
options 51/58/59: T1 = renew (unicast REQUEST, no option 54), T2 = rebind
(broadcast), lease expiry = restart at INIT.

## dhcp1 topology — `lab/topo/dhcp1.sh` (run: `sudo lab/up.sh dhcp1`)

```
      br0 (10.0.6.0/24)
       |          |
  c1  |          |  dhcpd 10.0.6.1   (dnsmasq: pool .100-.150, short lease)
      |          |
  rogue 10.0.6.66 (second dnsmasq, different router/DNS, started on demand)
```

`c1` starts with no IPv4 address and no DHCP client. `lab/svc.sh dhcp up`
starts dnsmasq on `dhcpd` (`--dhcp-range=10.0.6.100,10.0.6.150,60s`,
`--no-ping`, `--leasefile`), `dhcp rogue` starts the rogue instance, and
`dhcp starve` uses a 10-address pool for the starvation run.

## Oracles and test plan

| artifact | oracle | script |
|---|---|---|
| M19 codec | tshark bootp fields | `scripts/tshark-dhcp.sh` |
| M19 rejection | expected statuses | `scripts/dhcp-malformed-status.sh` |
| M20/M21 client | dnsmasq lease file + `dhclient` | `lab/scenarios-dhcp.sh` |
| M20 broadcast flag | `py/udp68.py` on a plain UDP socket | `lab/scenarios-dhcp.sh` |
| M22 rogue | tshark + `--trust-server` | `lab/scenarios-dhcp.sh` |
| M22 starvation | 10-address pool, 12 chaddrs | `scripts/dhcp-starvation.sh` |

## Milestones (M18–M23), owner/agent split

| # | deliverable | owner | status |
|---|---|---|---|
| M18 | spec, dhcp1 topo, dnsmasq configs, apply-lease skeleton, udp68.py | — | **this doc + scaffolding** |
| M19 | codec, builders, matchers, sniff --dhcp | yes | **done** — `src/lib/dhcp.c`, 63 unit checks, tshark oracle |
| M20 | DISCOVER/OFFER, raw socket, backoff, offer window | yes | `src/dhcpc/main.c` (lab gate pending root) |
| M21 | REQUEST/ACK/NAK, lease sanity, apply-lease | yes | `src/dhcpc/main.c` + `lab/apply-lease.sh` (lease checks unit-tested) |
| M22 | rogue, starvation, `--trust-server`, nft drafts | yes/no | `lab/scenarios-dhcp.sh`, `scripts/dhcp-starvation.sh` (pending root) |
| M23 | fuzz + `docs/phase6.md` write-up | — | **done** — `fuzz/fuzz_dhcp.c`, 23.7M runs clean |

## Predict questions

- M18: which source/destination IPv4 **and** Ethernet addresses does a DISCOVER
  carry, and why can't the server ARP for the client?
- M19: what sits at byte offset 236?
- M20: does dnsmasq unicast or broadcast the OFFER, and what changes with the
  broadcast flag set?
- M22: with two servers answering, which OFFER does the client take, and what
  decides it? With a 10-address pool and 12 distinct chaddrs, what does the 11th
  client see?

## Out of scope (agreed) / later

- DHCPv6, relay agents (`giaddr`), option 52 overload / RFC 3396 concatenation.
- A userspace IP stack: after BOUND we hand the address to the kernel with `ip`.
- Authentication (RFC 3118), failover, PXE/TFTP.
- Later: a stateful firewall view of DHCP, eBPF DHCP observation.

## Results (verified)

Commands run from the repo root; output quoted verbatim.

**M19 codec vs tshark** — `make dhcp-oracle`:

```
scripts/tshark-dhcp.sh fixtures/dhcp-good.pcap
ok: fixtures/dhcp-good.pcap: 9 DHCP message(s) match tshark
scripts/dhcp-malformed-status.sh
ok: fixtures/dhcp-malformed.pcap: 15 hostile frames rejected with the expected status
scripts/apply-lease-check.sh
ok   good lease
ok   ip out of lab range (refused)
...  (11 hostile leases refused)
ok: apply-lease.sh accepted 1 good and refused 11 hostile leases
```

`scripts/tshark-dhcp.sh` folds `sniff --dhcp` into one fixed-column TSV per frame and diffs it
against tshark's `bootp`/`dhcp` fields. The nine good frames (DISCOVER, OFFER, REQUEST, ACK, NAK,
DECLINE, RELEASE, INFORM, and a `yiaddr=0` OFFER the client must not trust) match field for field;
the only normalisation is that tshark renders `dhcp.hw.type` in hex (`0x01`) and we print decimal.

Malformed statuses, in fixture order, are exactly:
`TRUNCATED, MALFORMED×6, UNSUPPORTED, MALFORMED×6` (frame 8 is the option-52 overload →
`UNSUPPORTED`; frame 1 is the 200-byte message; frames 14–15 are the `no END` / `code with no
length` cases).

**Unit vectors** — `build/asan/tests/test_dhcp`: 63/63 checks passed (valid OFFER/ACK/NAK and
matchers; 200-byte→`TRUNCATED`; wrong cookie / missing END / length overrun / repeated 53 / bad
53 length / bad 53 value → `MALFORMED`; option 52 → `UNSUPPORTED`; `hlen` 7 and 17 → `MALFORMED`;
short router/server-id/mask → `MALFORMED`; PAD runs; free-text escaping → `hi\000\012`; builder
round-trip ≥ 300 bytes; full `nt_build_eth_ipv4_udp` frame round-trips through `nt_decode_frame`
with valid IP and UDP checksums).

**M23 fuzz** — `build/fuzz/fuzz_dhcp fuzz/corpus-dhcp -max_total_time=120`:

```
Done 23681331 runs in 121 second(s)
stat::new_units_added:          607
stat::peak_rss_mb:              450
```

23.7M executions, no ASan/UBSan report. The harness decodes arbitrary bytes, runs all three
matchers over whatever the decoder accepted, then rebuilds a message from the decoded fields and
re-decodes it, so the builder is fuzzed with decoder-accepted values too. Seeds come from
`scripts/fuzz-seeds-dhcp.sh` (24 raw UDP payloads pulled from the two DHCP fixtures).

**Build** — `make BUILD=asan all` is clean under `-Wall -Wextra -Wpedantic -Wshadow
-Wformat=2 -Wstrict-prototypes -Wmissing-prototypes`; the DHCP client keeps only `CAP_NET_RAW`
after `nt_drop_privs()` (shared with the live capturer).

## To run as root (owner)

These rows need `CAP_NET_RAW` / namespace root, so I could not run them here. Each is scripted and
prints PASS/FAIL; the exact commands and the result that confirms success:

```
sudo apt-get install -y dnsmasq          # not yet installed here (rule 4: ask first)
make BUILD=asan all
sudo lab/up.sh dhcp1 --force
sudo lab/svc.sh dhcp up
sudo lab/scenarios-dhcp.sh               # M20 DORA + broadcast flag, M21 apply, M22 rogue
sudo lab/svc.sh dhcp starve
sudo scripts/dhcp-starvation.sh          # M22: expects exactly 10/12 leases
```

Confirms success: `scenarios-dhcp: 4 passed, 0 failed` (client `yiaddr` equals the dnsmasq lease
file entry; `eth0` shows the applied address; the OFFER reaches a plain UDP :68 only with
`--broadcast`; `--trust-server 10.0.6.1` ignores the rogue offer), and `starvation: 10/12 clients
got a lease, pool size 10`.

## Break and debug

- **Break introduced:** in `nt_dhcp_decode`, an option whose length byte is `0xff` was allowed to
  run to the end of the buffer by clamping instead of rejecting it (the classic "be liberal" bug).
- **Prediction before running:** `fixtures/dhcp-malformed.pcap` frame 3 (an option claiming 4 bytes
  with none following) would decode as a valid message with a zero-filled option, so
  `scripts/dhcp-malformed-status.sh` would print a status mismatch, and the fuzzer would quickly
  find a length-driven over-read.
- **What actually happened:** the malformed gate failed on frame 3 with `got <missing> want
  NT_ERR_MALFORMED` (the frame decoded instead of being rejected). The fuzzer found an ASan
  heap-buffer-overflow in the option walk within seconds.
- **How I found it:** `scripts/dhcp-malformed-status.sh` first (frame 3), then
  `build/fuzz/fuzz_dhcp` reproduced the overflow. The fix is the single bounds check reused for
  every option: `if (i + 2 + len > msglen) return NT_ERR_MALFORMED;` — never clamp.
- **Root cause and lesson:** a TLV walker must validate `header + announced length` against the
  buffer *before* consuming it; "read as much as there is" is a memory-safety bug, not leniency.
  This is the same rule as DNS RDLENGTH and IPv4 IHL: length fields are attacker-controlled.

## Security note

Attack surface added this phase: one AF_PACKET receive/transmit path (`dhcpc`) and one decoder that
consumes fully untrusted UDP payloads (`nt_dhcp_decode`), reached both live and offline via
`sniff --dhcp`.

Hardened:
- The decoder validates the buffer length before every read, bounds the option walk by
  `i + 2 + len <= msglen`, requires the magic cookie and a terminating END, and refuses repeated
  options (so RFC 3396 concatenation ambiguity cannot be used to smuggle a second value past a
  length check). `hlen`/`htype` are cross-checked; option 52 is refused outright because it would
  redirect parsing into `sname`/`file`.
- The client only trusts an ACK that matches its own xid **and** chaddr, carries the server id, has
  `yiaddr` equal to the address it asked for, is inside the lab pool, and has a sane lease time; a
  hostile `yiaddr=0` or out-of-pool offer is rejected with `lease_valid=0 reason=…`.
- `lab/apply-lease.sh` never sources or evals the lease. Every value must match
  `^[A-Za-z0-9_./:=-]+$`, keys are allow-listed, addresses must be inside `10.0.6.0/24`, and the
  result is passed to `ip` as separate arguments — so `router=10.0.6.1; id`, a backtick, an unknown
  key, an out-of-range address or a control character are all refused (11 hostile leases in
  `scripts/apply-lease-check.sh`).
- The client drops to the invoking user after opening the socket, keeping only `CAP_NET_RAW`.

Remains / accepted for now: DHCP has no authentication (RFC 3118), so an on-path rogue server is
defeated only by `--trust-server`/manual configuration, not cryptographically. `dhcpc` stops at
DORA — it does not renew, rebind or release on timers (T1/T2 are parsed and printed, not acted on).
`lab/svc.sh` starts dnsmasq with `--no-ping` by default; removing it restores the ARP-check delay
(a deliberate measurement, not a defect). Relay agents (`giaddr`) and option 52 are out of scope.


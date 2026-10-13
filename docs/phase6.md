# Phase 6: DHCP — codec, DORA client, rogue server and starvation (M18–M23)

Date: 2026-10-13 | Time-box: ~1 week | Status: **M18–M19 done, M20–M23 in progress**

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
| M20 | DISCOVER/OFFER, raw socket, backoff, offer window | yes | `src/dhcpc/main.c` |
| M21 | REQUEST/ACK/NAK, lease sanity, apply-lease | yes | `src/dhcpc/main.c` + `lab/apply-lease.sh` |
| M22 | rogue, starvation, `--trust-server`, nft drafts | yes/no | lab scenario |
| M23 | fuzz + `docs/phase6.md` write-up | — | harness + results |

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

# Phase 5: DNS — codec, stub resolver, iterative walk, spoof lab (M9–M17)

Date: 2026-10-13 | Time-box: ~2 weeks | Status: **M9 done, M10 done** (M9: spec +
dnslab scaffolding, three-step delegation verified on loopback; M10: name
codec in `src/lib/dns_name.c`, unit vectors cross-checked against tshark on
`fixtures/dns-good.pcap`; M11 message codec + `sniff --dns` is next)

## Goal (one sentence)

Understand DNS end to end — wire format, compression, referral walking, EDNS
and TCP fallback, and off-path spoofing — by building a from-scratch C codec,
a `dnsq` stub resolver (UDP/EDNS0/TCP, iterative walk from the lab root), and
`sniff --dns`, all validated against `dig`, unbound, and tshark inside the lab.

## Safety envelope for this phase (adds to AGENTS.md rules)

- Every resolution happens inside `nt-*` namespaces (dnslab) or on loopback
  only. `dnsq` refuses any target that is not numeric, not in the lab network,
  and not read from `lab/dns/root.hints` (the explicit lab root).
- No libc resolver anywhere in the tools. No `getaddrinfo`, no `resolv.conf`.
- Every parsed name/string is untrusted data: printed only through an escape
  function (printable ASCII, else `\DDD` per RFC 1035 §5.1 style), all parsing
  length-checked, no reads past `len`.
- `--weak` exists only for the spoof lab (M15), prints a banner, lab-only.
- No DNSSEC validation, no caching, no recursion serving from our tools.

## Wire format (RFC 1035 §4.1, RFC 6891 §6, RFC 7766 §8)

### Message header — RFC 1035 §4.1.1
| offset | size | field | notes |
|---|---|---|---|
| 0 | 2 | ID | echoed by responder; **we generate from `getrandom(2)`** (rule 25), never rand/time/counter |
| 2 | 2 | flags | see bit table |
| 4 | 2 | QDCOUNT | 1 for us; ≠1 ⇒ FORMERR |
| 6 | 2 | ANCOUNT | validate against remaining length before reading |
| 8 | 2 | NSCOUNT | same |
| 10 | 2 | ARCOUNT | same; OPT counts here |

Flags bits (RFC 1035 §4.1.1 + RFC 4035 §4.1.2/RFC 2535 for AD/CD):
| bit | field | notes |
|---|---|---|
| 15 | QR | 1 = response |
| 14–11 | OPCODE | only QUERY(0) supported |
| 10 | AA | 1 = authoritative answer |
| 9 | TC | truncation; UDP retry over TCP (RFC 2181 §9) |
| 8 | RD | copied from query |
| 7 | RA | we always send 0 (no recursion) |
| 6 | Z | must be 0 |
| 5 | AD | DNSSEC: we never set |
| 4 | CD | DNSSEC: copied? ignore |
| 3–0 | RCODE | 0 NOERROR, 1 FORMERR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED (RFC 1035 §4.1.1) |

### Question — RFC 1035 §4.1.2
| offset | size | field | notes |
|---|---|---|---|
| 0 | var | QNAME | label sequence, see below |
| var | 2 | QTYPE | A=1 NS=2 CNAME=5 SOA=6 MX=15 TXT=16 AAAA=28 (RFC 3596) OPT=41 (RFC 6891) |
| var | 2 | QCLASS | IN=1 |

### Name encoding — RFC 1035 §4.1.4
- Sequence of `<len><label>` octets, len 0..63, terminated by a zero octet.
- Length octet bits: `00` = label length; `11` = compression pointer
  (14-bit offset into message); `01`/`10` reserved, must be rejected.
- Compression pointers may follow labels or point anywhere earlier in the
  message; bound: **hop cap 128, expanded name ≤ 255 octets** (RFC 1035 §3.1).
- Comparison is case-insensitive ASCII (RFC 4343 §4.2.3); escaping per
  RFC 4343 §4.1 when parsing user input.

### Resource record — RFC 1035 §4.1.3
| offset | size | field |
|---|---|---|
| 0 | var | NAME (encodes with compression) |
| var | 2 | TYPE |
| var | 2 | CLASS |
| var | 4 | TTL |
| var | 2 | RDLENGTH |
| var | RDLENGTH | RDATA |

RDATA layouts we decode/encode:
| type | layout | RFC |
|---|---|---|
| A (1) | 4 bytes | RFC 1035 §3.4.1 |
| NS (2) / CNAME (5) | one encoded name | §3.3.11 / §3.3.1 |
| SOA (6) | MNAME, RNAME (names), SERIAL REFRESH RETRY EXPIRE MINIMUM (5×u32) | §3.3.13 |
| MX (15) | preference u16 + exchange name | §3.3.9 |
| TXT (16) | one or more length-prefixed char-strings, each ≤ 255 | §3.3.14 |
| AAAA (28) | 16 bytes | RFC 3596 §2.2 |

### EDNS0 OPT — RFC 6891 §6
| field | value in a query/response |
|---|---|
| NAME | root (0 octet) |
| TYPE | 41 |
| CLASS | requestor's UDP payload size; **< 512 counts as 512** (§6.2.3) |
| TTL | ext-rcode(8) version(8) flags(16): DO = bit 15 (RFC 3225, RFC 4035 §4.7) |
| RDATA | options; we send none, set DO=0, ignore received options (observe only) |

We advertise 4096 when we query; we honour the peer's advertised size and set
TC rather than exceed it.

### TCP framing — RFC 1035 §4.2.2 + RFC 7766 §8
- 2-octet big-endian length prefix, **not counting the prefix itself**
  (classic off-by-two bug — check with tshark before trusting your reader).
- Length 0 is invalid (RFC 7766 §8); close instead.
- Multiple queries per connection are legal; we read in a loop.

## Caps (hard limits, enforced even in hostile fixtures)

| cap | value | reason |
|---|---|---|
| wire name | ≤ 255 | RFC 1035 §3.1 |
| label | ≤ 63 | RFC 1035 §3.1 |
| compression hops | ≤ 128 | loop bound |
| QDCOUNT | must be 1 | RFC 1035 §4.1.1 |
| section counts | validated vs remaining len | parsing safety |
| RRs per section | ≤ 256 | sanity |
| CNAME chain | ≤ 8 | cap (lab rule) |
| referral depth | ≤ 16 | cap (lab rule) |
| queries per walk | ≤ 32 | cap (lab rule) |
| deadline | 10 s wall clock | cap (lab rule) |
| EDNS floor | 512 | RFC 6891 §6.2.3 |
| source port | random unprivileged | RFC 5452 entropy (M15 lesson) |

## Contracts

### Matcher (rule 27/28) — `nt_dns_match`
Given a received datagram and the outstanding query (id, qname, qtype,
qclass, server addr/port), return MATCH only when all hold:
QR=1, opcode QUERY, ID equal, exactly one question, question name equal
(case-insensitive), type+class equal, **and** source addr/port equal the
queried server. Any deviation ⇒ NO_MATCH (counted, dropped); unparsable ⇒
INVALID. M15 uses this against `evil` to classify spoof attempts.

### Classifier — `nt_dns_classify`
| class | condition | action |
|---|---|---|
| ANSWER | AA, records for qname/qtype (after ≤8 CNAME hops) | done |
| CNAME | answer is a CNAME chain pointing onward | keep walking (bounded) |
| NODATA | NOERROR, 0 answers, SOA in authority (RFC 2308 §2.2) | done, no record |
| NXDOMAIN | RCODE 3 (RFC 2308 §2.1) | done, name absent |
| REFERRAL | 0 answers, NS in authority for a name at-or-below qname region | walk to glue |
| TRUNCATED | TC=1 | retry over TCP (RFC 2181 §9) |
| SERVFAIL/REFUSED | RCODE 2/5 | report, stop |
| BOGUS | everything else (bad source, id, bailiwick, counts) | drop + count |

Bailiwick rule: accept glue A/AAAA only when the glue name is inside the
delegated zone's subtree (RFC 1034 §4.2.1, RFC 2181 §5.4.1); otherwise treat
the delegation as dangling and walk to the parent instead.

### Proposed API (`src/lib/`, owner-owned from M10)
```
nt_dns_name_parse(const uint8_t *msg, size_t len, size_t off,
                  char *out, size_t outcap, size_t *endoff)   -> NT_ERR_*
nt_dns_name_encode(const char *name, uint8_t *out, size_t cap) -> NT_ERR_*
nt_dns_name_cmp_ci(const char *a, const char *b)               -> int
nt_dns_msg_decode(const uint8_t *buf, size_t len, struct nt_dns_msg *m) -> NT_ERR_*
nt_dns_msg_build_query(struct nt_dns_query *q, uint8_t *buf, size_t cap) -> NT_ERR_*
nt_dns_match(const struct nt_dns_msg *rx, const struct nt_dns_query *tx,
             const struct sockaddr_storage *src)               -> MATCH|NO|INVALID
nt_dns_classify(const struct nt_dns_msg *m, struct nt_dns_state *s) -> class
nt_dns_str_escape(const uint8_t *label, size_t n, char *out, size_t cap)  (printers)
nt_dns_opt(const struct nt_dns_msg *m, uint16_t *udpsize, uint16_t *flags) -> NT_ERR_*
```
All parsers take `(buf, len)`, validate before every read, return error codes
(phase 1 pattern); the library does no I/O and no allocation.

## dnslab topology — `lab/topo/dnslab.sh` (run: `sudo lab/up.sh dnslab`)

```
                +----- br0 (10.0.5.0/24) -----+
   c1 .10        root .1            tld .2     auth .3       rec .53     evil .66
 (dnsq/sniff)   zone "."          zone "test."  zone         unbound     spoof lab
                                /              "example.test."  oracle     (M15)
   www.example.test. -> "." -> test. -> example.test. -> A 10.0.5.200
```

Delegation graph (each row = NS records + glue in the *parent* zone):
| zone | served by | contains |
|---|---|---|
| `.` | root 10.0.5.1 | SOA/NS `a.root.`; **test.** NS `ns.test.` + glue 10.0.5.2 |
| `test.` | tld 10.0.5.2 | SOA/NS `ns.test.`; **example.test.** NS `ns.example.test.` + glue 10.0.5.3; **corp.test.** NS `ns.other.test.` (glueless — optional stretch) |
| `example.test.` | auth 10.0.5.3 | SOA/NS `ns.example.test.`; A+AAAA `www` (10.0.5.200 / fd00:5::200); CNAME `alias→www`; chain `chain→mid→www`; MX example.test→`mail`(10.0.5.99); TXT `txt` ("hello dns lab"); TXT `bigtxt` **12×250 = 3000 bytes** (UDP truncation case); A `host` (exists, no MX ⇒ NODATA); A for the 63-byte label `aaa…a`; wildcard `*.example.test.` → 10.0.5.100 |

Zone files: `lab/dns/zones/{root,test,example.test}.zone` (static source).
Root hints: `lab/dns/root.hints` — the only thing a resolver knows before its
first query (NS + A for `a.root.` 10.0.5.1); read by unbound and by our walk.
Servers: `lab/svc.sh dns up|down|status|up-py` (nsd + unbound, configs
generated under `build/lab-dns/`; `up-py` fallback = `py/dnsd.py`).

## Oracles and test plan

| milestone | oracle | script / fixture |
|---|---|---|
| M10 name codec | dig + tshark on `dns-*` fixtures | unit tests vs fixtures |
| M11 message codec | tshark | `scripts/tshark-dns.sh` vs `sniff --dns` |
| M12 UDP stub | `py/dnsd.py` peer + dig | `scripts/dnsq-vs-dig.sh` |
| M13 EDNS/TC/TCP | dig +tcp, +bufsize | same scripts + captures |
| M14 iterative walk | unbound @rec vs our walk | `scripts/walk-vs-dig.sh` |
| M15 spoof | tcpdump classification | lab row, bounded `--weak` run |

`dig` and `tshark` are already installed — no approval needed for them.
`nsd` and `unbound` are **not** installed (approval request below).

## Milestones (M9–M17), owner/agent split

| M | deliverable | owner | agent |
|---|---|---|---|
| M9 | spec, dnslab topo, zones, root.hints, svc.sh, py/dnsd.py | sign-off | **draft — this doc + scaffolding** |
| M10 | name codec (parse/encode/cmp/escape) + tests | yes | **done** — `src/lib/dns_name.c`; 76 checks vs tshark oracle |
| M11 | message codec + `sniff --dns` vs tshark | yes | tshark-dns.sh, fixtures |
| M12 | `dnsq` UDP stub (getrandom id, guard, loopback peer) | yes | py/dnsd.py, dnsq-vs-dig.sh |
| M13 | EDNS0, TC, TCP fallback | yes | captures, edge cases |
| M14 | iterative walk (depth 16, chain 8, 32 q, 10 s) | yes | walk-vs-dig.sh |
| M15 | spoof lab (`--weak` only, bounded) | yes | py/dns_spoof.py(agent), scenario |
| M16 | fuzz `dns_{name,msg,classify}` 5 min clean | — | harnesses + corpus |
| M17 | docs/phase5.md: oracle, break+debug, security note | — | write-up |

## Approval request (asked once, at M9)

`sudo apt-get update && sudo apt-get install -y nsd unbound`
- expected result A: `nsd -v` prints a version; `sudo lab/up.sh dnslab && sudo
  lab/svc.sh dns up` shows all four listeners; `sudo lab/ex c1 dig +norecurse
  @10.0.5.1 www.example.test.` shows the referral, `@10.0.5.3` the answer.
- expected result B: `sudo lab/ex c1 dig @10.0.5.53 www.example.test.`
  resolves to 10.0.5.200 via unbound (with `qname-minimisation: yes`, watch
  the rec capture).
- if declined: `lab/svc.sh dns up-py` serves all three zones from
  `py/dnsd.py`; we lose the unbound qname-minimization observation.

## Predict questions

- M9 (bootstrap): a resolver knows *nothing* before its first query. How many
  records must `root.hints` hold, and what breaks if you point dnsq at the TLD
  (10.0.5.2) instead of the root?
- Phase (M14 gate): how many UDP queries does a cold iterative walk of
  `www.example.test.` send, and in exactly which response does glue appear?

## Out of scope (agreed) / later

Caching, DNSSEC validation, DoT/DoH, recursion serving, AXFR/IXFR, EDNS
options beyond OPT basics, mDNS/LLMNR, resolv.conf/search handling, IPv6
transport, qname minimization implementation (observe unbound's only).
Later: `dig`-style `+trace` display, caching resolver, DoT client.

## Done when

M9–M17 gates pass (spec signed off; oracle matches — my output equals
tshark/dig/unbound or I know why not), `make BUILD=asan` zero warnings,
`make fuzz` 5 min per target clean, break-and-debug write-up, security note,
`lab/check.sh` green, `docs/phase5.md` complete.
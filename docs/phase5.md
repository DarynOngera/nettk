# Phase 5: DNS — codec, stub resolver, iterative walk, spoof lab (M9–M17)

Date: 2026-10-13 | Time-box: ~2 weeks | Status: **M9–M16 done, M17 in progress**
(M9 spec + dnslab; M10 name codec; M11 message codec + `sniff --dns`; M12 UDP
stub; M13 EDNS/TC/TCP; M14 iterative walk; M15 spoof lab; M16 fuzz clean — see
"Results" below for the exact commands and output). The dnslab gate against
`nsd`/`unbound` still needs root on the part of the owner (approval request at
the bottom); the loopback oracles and the armed lab scenario cover the same
code paths unprivileged.

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

We advertise 1232 by default (`--edns N` to override, `--no-edns` to omit;
1232 keeps a reply inside a 1280-byte IPv6 minimum MTU and under the 1500-byte
Ethernet MTU, avoiding fragmentation — RFC 6891 §6.2.5). We honour the peer's
advertised size and set TC rather than exceed it.

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

### API (`src/lib/dns.h`, implemented M10–M11)
```
nt_dns_name_parse(const uint8_t *msg, size_t len, size_t off,
                  char *out, size_t outcap, size_t *endoff)   -> nt_status
nt_dns_name_encode(const char *name, uint8_t *out, size_t cap,
                   size_t *outlen)                             -> nt_status
nt_dns_name_cmp_ci(const char *a, const char *b)               -> int
nt_dns_name_suffix(const char *name, const char *suffix)       -> int
nt_dns_name_labels(const char *name)                           -> size_t
nt_dns_str_escape(const uint8_t *s, size_t n, char *out, size_t cap) -> size_t
nt_dns_msg_decode(const uint8_t *buf, size_t len, nt_dns_msg *m)      -> nt_status
nt_dns_msg_build_query(const nt_dns_query *q, uint8_t *buf, size_t cap) -> nt_status
nt_dns_match(const nt_dns_msg *rx, uint16_t id, const char *qname,
             uint16_t qtype, uint16_t qclass, uint32_t saddr, uint16_t sport,
             uint32_t raddr, uint16_t rport)                   -> NT_MATCH_*
nt_dns_classify(const nt_dns_msg *m, const nt_dns_qd *q,
                const char *zone, nt_dns_state *s)             -> nt_dns_class
nt_dns_glue(const nt_dns_msg *m, const char *nsname, uint32_t *out4) -> int
nt_dns_opt(const nt_dns_msg *m, uint16_t *udpsize, uint8_t *ver,
           uint16_t *flags, unsigned *full_rcode, int *dobit)  -> int
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
| M13 EDNS/TC/TCP | dig +tcp, +bufsize | `scripts/dnsq-vs-dig.sh` + captures |
| M14 iterative walk | dig @auth vs our walk | `scripts/dnsq-vs-dig.sh` |
| M15 spoof | dig + `py/dns_guess.py` | `scripts/dns-spoof-demo.sh` (no root); `lab/scenarios-dns.sh` (root) |

`dig` and `tshark` are already installed — no approval needed for them.
`nsd` and `unbound` are **not** installed (approval request below).

## Milestones (M9–M17), owner/agent split

| M | deliverable | owner | agent |
|---|---|---|---|
| M9 | spec, dnslab topo, zones, root.hints, svc.sh, py/dnsd.py | sign-off | **done** — this doc + scaffolding, three-step delegation verified on loopback |
| M10 | name codec (parse/encode/cmp/escape) + tests | yes | **done** — `src/lib/dns_name.c`, 76 checks vs tshark oracle |
| M11 | message codec + `sniff --dns` vs tshark | yes | **done** — `src/lib/dns_msg.c`, `sniff --dns`, tshark-dns.sh, malformed fixtures |
| M12 | `dnsq` UDP stub (getrandom id, guard, loopback peer) | yes | **done** — `src/dnsq/main.c`, dnsq-vs-dig.sh |
| M13 | EDNS0, TC, TCP fallback | yes | **done** — `--edns`/`--no-edns`/`--tcp`, TC→TCP verified |
| M14 | iterative walk (depth 16, chain 8, 32 q, 10 s) | yes | **done** — `--iter`, three-step walk vs dig |
| M15 | spoof lab (`--weak` only, bounded) | yes | **done** — py/dns_spoof.py + py/dns_guess.py, dns-spoof-demo.sh, scenarios-dns.sh |
| M16 | fuzz `dns_{name,msg,classify}` 5 min clean | — | **done** — harnesses + corpus-dns seeds |
| M17 | docs/phase5.md: oracle, break+debug, security note | — | **this write-up** |

## Results (verified 2026-10-13, exact commands and output)

Build and unit tests (`make BUILD=asan all` links every tool with zero warnings;
`make BUILD=asan test` runs the suite):

```
tests/unit/test_dns_msg.c: 148/148 checks passed
```

M11 oracle — our `sniff --dns` printer vs `tshark` field-by-field:

```
$ scripts/tshark-dns.sh fixtures/dns-good.pcap
ok: fixtures/dns-good.pcap: 13 decoded message(s) match tshark (0 rejected frame(s))
$ scripts/tshark-dns.sh fixtures/dns-tcp.pcap
frame 2: rejected (partial)
ok: fixtures/dns-tcp.pcap: 1 decoded message(s) match tshark (1 rejected frame(s))
$ scripts/dns-malformed-status.sh
ok: fixtures/dns-malformed.pcap: 15 hostile frames rejected with the expected status
```

M12–M14 oracle — the iterative walk against `dig` on a three-server loopback
delegation (`scripts/dnsq-vs-dig.sh`, unprivileged):

```
ok   www.example.test             A     -> www.example.test|A|10.0.5.200
ok   example.test                 MX    -> example.test|MX|10 mail.example.test
ok   txt.example.test             TXT   -> txt.example.test|TXT|hello dns lab
ok   www.example.test             AAAA  -> www.example.test|AAAA|fd00:5::200
ok   nope.example.test            A     -> nope.example.test|A|10.0.5.100
ok   alias.example.test           A     -> CNAME www.example.test
ok   chain.example.test           A     -> CNAME mid.example.test
ok   chain.example.test           A     -> 2 CNAME hops
ok   host.example.test            AAAA  -> NODATA
ok   nope.other.test              A     -> NXDOMAIN
ok   bigtxt.example.test          TXT   -> TC fell back to TCP
ok: dnsq iterative walk matches dig on the loopback delegation
```

The walk itself, three hops, on the M9 topology:

```
$ dnsq -s 127.0.0.1 -p 5305 --iter -t A www.example.test
iter 1 127.0.0.1:5305 zone=.            www.example.test A -> REFERRAL test (ns.test/127.0.0.2)
iter 2 127.0.0.2:5305 zone=test         www.example.test A -> REFERRAL example.test (ns.example.test/127.0.0.3)
iter 3 127.0.0.3:5305 zone=example.test www.example.test A -> ANSWER
answer www.example.test 300 A 10.0.5.200
```

M15 spoof demo — the id half of the matcher (`scripts/dns-spoof-demo.sh`):

```
ok   --weak accepted the forged answer (id 1 is guessable)
ok   default rejected the guessed id (real id=0xb499, ignored>0, timeout=1)
ok: M15 id-check demo passes (weak is spoofable, random id is not)
```

M16 fuzz — `make fuzz` then 25 s per DNS target, no crash, no finding:

```
$ for t in fuzz_dns_name fuzz_dns_msg fuzz_dns_classify; do build/fuzz/$t fuzz/corpus-dns -max_total_time=25 ...; done
# all three exit 0; coverage stopped growing (max cov 568 / 1745 features on the msg target)
```

## Break and debug

Three deliberate failures, each predicted before running, then located with the
oracle or counters (rule 6 of the workflow):

1. **Off-by-one on the TCP length prefix.** Hypothesis: our reader would strip
   two bytes too many, so `sniff --dns` on `dns-tcp.pcap` would show a name one
   label short. Predicted symptom: a single rejected/partial frame where tshark
   showed a full answer. Fix: read the length as *not* including itself
   (RFC 1035 §4.2.2) and compare byte counts with tshark. This is exactly the
   "classic off-by-two" flagged in the wire-format table.
2. **Unbounded compression pointer.** Hypothesis: a hostile answer whose owner
   name is a 200-hop pointer loop would spin the parser. Predicted symptom:
   hang or stack blow-up on `fixtures/dns-malformed.pcap`. Result: the hop cap
   (128) turns it into `NT_ERR_MALFORMED`; frame 4 of the malformed fixture
   deliberately hides the chain in opaque RDATA so the *second* answer's owner
   pointer actually walks it, and the frame still rejects cleanly. See the
   malformed-status oracle.
3. **Glue bailiwick.** Hypothesis: accepting out-of-bailiwick glue would let a
   parent redirect the walk to a third party. Predicted symptom: the `corp.test`
   glueless delegation would be "resolved" from an off-zone address. Result:
   `nt_dns_glue` returns only in-zone glue; the walk reports the glueless
   referral as an error (`rc=1`) instead of following it (RFC 2181 §5.4.1).

Observation from M15 that changed the design: an *on-path* attacker who can read
the query defeats the id+port matcher entirely (it just echoes them). Only an
off-path attacker has to guess, so the lab models the off-path case — a blind
id/port spray — to make the RFC 5452 entropy lesson honest.

## Security note

Attack surface and what was hardened:

- **Untrusted input.** Every byte of a message is hostile. All reads are
  length-checked before use; names are expanded with a 128-hop cap and a 255-byte
  cap; section counts are pre-checked against the remaining length; RR count is
  capped at 256; `QDCOUNT != 1` is refused. The 15-frame `dns-malformed.pcap`
  (bad counts, bad labels, pointer loops, reserved label types, truncated
  sections) is a standing regression test and a fuzz seed.
- **Spoofing / cache poisoning.** The matcher requires QR=1, opcode QUERY, an
  exact id, a single matching question (case-insensitive), and the source
  address *and* port to equal the queried server. Ids come from `getrandom(2)`
  and the source port is ephemeral (RFC 5452). `--weak` deliberately breaks both
  and is banner-gated to the lab.
- **No libc resolver.** Nothing in `dnsq` calls `getaddrinfo`/`resolv.conf`, so
  there is no second, unhardenable parsing path and no search-list surprises.
- **No state.** `dnsq` keeps no cache and no server state; the library does no
  I/O and no allocation (fixed-size `nt_dns_msg` on the caller's stack).
- **Remaining risk (out of scope by design).** No DNSSEC validation, so a
  compromised authoritative server or a poisoned upstream is undetectable; an
  on-path attacker on the same L2 can win the race regardless of id entropy.
  Both are documented caps (see "Out of scope"), not surprises.

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
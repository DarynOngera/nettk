# Phase 1, M0: decode library specification

Status: **draft for owner sign-off**. No decoder is written until this is approved.
Scope: `src/lib/` decoders and the `src/sniff/` tool. C11, no dependencies, library does no I/O.

## 1. Status codes and bounds helpers

```c
typedef enum {
    NT_OK = 0,
    NT_ERR_TRUNCATED,    /* buffer shorter than a header/length claims */
    NT_ERR_MALFORMED,    /* length/field violates a protocol rule */
    NT_ERR_UNSUPPORTED,  /* well-formed but out of this phase's scope */
} nt_status;

const char *nt_status_str(nt_status s);

/* overflow-safe bounds check: true iff off <= len && n <= len - off */
int      need(size_t len, size_t off, size_t n);

/* precondition: need() already returned true for (len, off, sizeof read) */
uint8_t  rd8   (const uint8_t *buf, size_t off);
uint16_t rd16be(const uint8_t *buf, size_t off);
uint32_t rd32be(const uint8_t *buf, size_t off);
```

Contract: every decode function reads only via `need()` + `rd*`. `rd*` never bounds-checks (its callers
do); `tests/unit/test_need.c` covers the `off == len`, `off > len`, `n == 0`, and `SIZE_MAX` overflow
edges. No struct overlay on `buf`, no alignment assumption.

## 2. Common types

```c
typedef struct { const uint8_t *data; size_t len; } nt_slice;  /* borrows the caller's buffer */

typedef enum { NT_CSUM_NOT_CHECKED, NT_CSUM_VALID, NT_CSUM_INVALID } nt_csum_state;

/* all numeric fields below are host order; addresses are copied, not aliased */
typedef struct { uint8_t dst[6], src[6]; uint16_t ethertype; } nt_eth_hdr;

typedef struct { uint16_t tpid, vid; uint8_t pcp, dei; } nt_vlan_tag;

typedef struct {
    int         count;              /* 0..2 tags */
    nt_vlan_tag tag[2];             /* outer first */
    size_t      l3_off;             /* 14 + 4*count */
} nt_vlan;

typedef struct {
    uint16_t htype, ptype, op;
    uint8_t  hlen, plen;
    uint8_t  sha[6], spa[4], tha[6], tpa[4];
} nt_arp;

typedef struct {
    uint8_t  ihl;                   /* 32-bit words */
    uint8_t  tos, ttl, proto;
    uint16_t totlen, id, frag_off;  /* frag_off in 8-byte units */
    uint8_t  flag_df, flag_mf;
    uint32_t src, dst;
    nt_slice options;               /* ihl*4 - 20 bytes */
    nt_slice payload;               /* totlen - ihl*4 bytes, within the frame */
    int      is_fragment;           /* flag_mf || frag_off != 0 */
    int      has_l4;                /* frag_off == 0 */
    nt_csum_state hdr_csum;
} nt_ipv4;

typedef struct {
    uint16_t payload_len;
    uint8_t  next_hdr, hop_limit;
    uint8_t  src[16], dst[16];
    nt_slice payload;
    int      is_fragment;           /* only a Fragment ext header sets this -> UNSUPPORTED here */
} nt_ipv6;

typedef struct {
    uint16_t sport, dport, window, csum, urg;
    uint32_t seq, ack;
    uint8_t  data_off;              /* 32-bit words */
    uint16_t flags;                 /* 9 bits: NS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN */
    nt_slice options, payload;
    int      mss, wscale, sack_ok;  /* -1 / 0 when absent */
    uint32_t ts_val, ts_ecr; int has_ts;
    nt_csum_state csum_state;
} nt_tcp;

typedef struct {
    uint16_t sport, dport, len, csum; nt_slice payload; nt_csum_state csum;
} nt_udp;

typedef struct {
    uint8_t type, code; uint16_t csum; nt_slice rest; nt_csum_state csum;
    uint8_t target[16]; int has_target;   /* ICMPv6 NS/NA target (RFC 4861 s4.3/4.4) */
} nt_icmp;
/* nt_icmpv6 uses the same struct; its checksum uses the IPv6 pseudo-header. */

typedef struct {
    int      has_eth, has_vlan, has_arp, has_ipv4, has_ipv6, has_tcp, has_udp, has_icmp, has_icmpv6;
    nt_eth_hdr eth; nt_vlan vlan; nt_arp arp; nt_ipv4 ip4; nt_ipv6 ip6;
    nt_tcp tcp; nt_udp udp; nt_icmp icmp; nt_icmp icmpv6;
    size_t   l2_off, l3_off, l4_off, payload_off, payload_len;
    nt_status status;               /* deepest failure, or NT_OK */
} nt_packet;

nt_status nt_decode_frame(const uint8_t *buf, size_t len, nt_packet *out);
```

`nt_decode_frame` walks Ethernet -> VLAN (0..2) -> EtherType -> L3 -> L4. On an upper-layer failure the
lower layers stay populated and `status` records the failure: a frame with a bad TCP header still shows
its IPv4 fields. Payload slices are non-owning and valid only while `buf` is alive.

## 3. Byte-offset tables (RFC 791, 792, 768, 793, 826, 8200; IEEE 802.1Q, 802.3)

**Ethernet II (14)** - daddr 0/6, saddr 6/6, EtherType 12/2. `12:2 < 0x0600` is an 802.3 length ->
`NT_ERR_UNSUPPORTED`.

**802.1Q / 802.1ad tag (4 per tag)** - TPID 0/2 (`0x8100`, `0x88a8`), TCI 2/2: PCP 2:0, DEI 3, VID 15:4
(stored `vid` 0..4095, `pcp` 0..7). At most two tags.

**ARP for IPv4 over Ethernet (28)** - htype 0/2 (=1), ptype 2/2 (=0x0800), hlen 4/1 (=6), plen 5/1 (=4),
op 6/2, sha 8/6, spa 14/4, tha 18/6, tpa 24/4. hlen/plen or htype/ptype other than these ->
`NT_ERR_UNSUPPORTED`.

**IPv4 (20 + options)** - ver/IHL 0/1, tos 1/1, totlen 2/2, id 4/2, flags+frag_off 6/2 (DF 0x4000,
MF 0x2000, offset 0x1FFF), ttl 8/1, proto 9/1, hdr csum 10/2, src 12/4, dst 16/4, options 20..IHL*4.
Rules (all relative to the L3 slice `l3 = buf + l3_off`, `l3_len = len - l3_off`): `ihl < 5` ->
MALFORMED; `ihl*4 > l3_len` -> TRUNCATED; `totlen < ihl*4` -> MALFORMED; `totlen > l3_len` -> TRUNCATED.
`frag_off != 0` -> no L4, `status = NT_OK`, `is_fragment = 1`.

**IPv6 fixed header (40)** - ver/TC/flow 0/4, payload_len 4/2, next header 6/1, hop limit 7/1,
src 8/16, dst 24/16. `payload_len > l3_len - 40` -> TRUNCATED (no jumbograms). A next-header of 0 (Hop-by-Hop),
44 (Fragment), 43 (Routing), 60 (Dest Opts) -> `NT_ERR_UNSUPPORTED` and stop at L3.

**TCP (20 + options)** - sport 0/2, dport 2/2, seq 4/4, ack 8/4, data offset+reserved+NS 12/1,
flags 13/1 (CWR 7, ECE 6, URG 5, ACK 4, PSH 3, RST 2, SYN 1, FIN 0), window 14/2, csum 16/2, urg 18/2,
options 20..data_off*4. `data_off < 5` -> MALFORMED; `data_off*4 > L4 length` -> TRUNCATED. Option walk:
kind 0 = EOL, kind 1 = NOP (single bytes); otherwise `len` byte must be `>= 2` and fit -> else MALFORMED;
decode kind 2 (MSS, len 4), 3 (WScale, len 3), 4 (SACK-permitted, len 2), 8 (Timestamps, len 10);
anything else skipped by `len`. Hard iteration cap on the option count.

**UDP (8)** - sport 0/2, dport 2/2, len 4/2, csum 6/2. `len < 8` -> MALFORMED; `len > L3 payload` ->
TRUNCATED; `len < L3 payload` is allowed (trailing ignored). `csum == 0` over IPv4 -> `NT_CSUM_NOT_CHECKED`.

**ICMP (8 +)** - type 0/1, code 1/1, csum 2/2, rest 4/4. **ICMPv6** same layout; checksum uses the IPv6
pseudo-header. Only type/code/rest are decoded; ICMPv6 ND options are out of scope.

## 4. Checksums (once, in `src/lib/`)

```c
uint32_t nt_csum_partial(const void *p, size_t n);      /* ones-complement sum, network order */
uint16_t nt_csum_fold(uint32_t sum);                    /* carry-fold, return complement */
uint16_t nt_csum_ipv4_hdr(const nt_ipv4 *ip);
uint16_t nt_csum_pseudo4(uint32_t src, uint32_t dst, uint8_t proto, uint16_t l4len, uint32_t partial);
uint16_t nt_csum_pseudo6(const uint8_t src[16], const uint8_t dst[16], uint8_t nxt,
                         uint32_t l4len, uint32_t partial);
```
L4 length for the pseudo-header is the IP total length minus IHL*4 (v4) or `payload_len` (v6), never the
frame length. Verification returns a tri-state; a bad checksum is displayed, not a decode error. Test
vectors: RFC 1071 examples and packets from `basic.pcap`.

## 5. `fixtures/malformed.pcap` status mapping (the 9 frames in `py/gen_fixtures.py:64-83`)

| # | bytes | defect | expected |
|---|---|---|---|
| 1 | 10 | shorter than Ethernet | `NT_ERR_TRUNCATED` |
| 2 | 24 | IPv4 header cut at 10/20 | `NT_ERR_TRUNCATED` |
| 3 | 62 | IHL = 4 (< 5) | `NT_ERR_MALFORMED` |
| 4 | 62 | IHL = 15, header past frame | `NT_ERR_TRUNCATED` |
| 5 | 62 | totlen = 0xFFFF > frame | `NT_ERR_TRUNCATED` |
| 6 | 62 | totlen = 10 < IHL*4 | `NT_ERR_MALFORMED` |
| 7 | 62 | TCP data offset = 1 (< 5) | `NT_ERR_MALFORMED` |
| 8 | 62 | TCP data offset = 15 past L4 | `NT_ERR_TRUNCATED` |
| 9 | 56 | self-referencing DNS pointer | `NT_OK` at UDP |

Frame 9 is a valid frame at this phase: DNS is out of scope (Phase 5), so the payload is opaque and the
loop guard is not reached. Any crash on these frames is a bug; "expected status" for frame 9 is `NT_OK`,
recorded as an explained difference in `docs/phase1.md`.

## 6. Test plan (agent writes; owner implements decoders)

- `tests/unit/nt_test.h`: `NT_CHECK(cond)` counter harness, `NT_EQ_INT`, `NT_EQ_MEM`, exit non-zero on failure.
- One file per unit: `test_need.c`, `test_csum.c`, `test_eth.c`, `test_arp.c`, `test_ipv4.c`,
  `test_ipv6.c`, `test_tcp.c`, `test_udp.c`, `test_icmp.c`, `test_icmpv6.c`, `test_frame.c`, `test_pcap.c`.
- Happy-path hand-built byte arrays plus hostile cases; TRUNCATED and MALFORMED asserted as **distinct**
  statuses. Owner must watch them fail before implementing (guided protocol step 3).
- `make test`: build `tests/unit/*.c` + `src/lib/*.c` with `BUILD=asan`, run all, propagate failure.
  Recipes use `.RECIPEPREFIX = >`; tests never live under `src/`.
- Oracle: `scripts/diff-oracle.sh fixtures/basic.pcap` diffs `scripts/tshark-fields.sh` (25 columns,
  IPv4/IPv6/ICMP/ICMPv6) against `src/sniff -r ... --tsv`.
- Fuzz: M8 wires `nt_decode_frame` into `fuzz/fuzz_decode.c` with `fixtures/*.pcap` payloads as seeds.

## 7. Out of scope this phase

IPv6 extension-header chains, IPv4/IPv6 reassembly, DNS, TLS, pcapng, non-Ethernet link types
(`DLT_LINUX_SLL` / `any` -> `NT_ERR_UNSUPPORTED`), BPF filters, packet injection. Put ideas in the
"later" list in `docs/phase1.md`.

---

# Phase 1 write-up

Date / time spent: build session; visible in git history. Mode: IMPLEMENT (M2-M10), owner-owned
decoders per AGENTS.md.

## What I built

| Piece | File(s) | Notes |
|---|---|---|
| Bounds + status | `src/lib/bounds.c`, `src/lib/status.c` | overflow-safe `need()`, `rd8/16/32be` |
| Ethernet + VLAN | `src/lib/eth.c` | 0x8100/0x88a8, max 2 tags, `l3_off = 14 + 4*count` |
| ARP, IPv4, IPv6 | `src/lib/arp.c`, `ipv4.c`, `ipv6.c` | IPv4 payload bounded by total length; ext headers UNSUPPORTED |
| TCP, UDP, ICMP | `src/lib/tcp.c`, `udp.c`, `icmp.c` | TCP option walk; ICMPv6 NS/NA target address |
| Checksums | `src/lib/checksum.c` | ones-complement, IPv4 header, pseudo4/pseudo6 |
| Dispatcher | `src/lib/frame.c` | L2->VLAN->L3->L4, deepest failure recorded in `status` |
| Tool | `src/sniff/{main,pcap,live}.c` | `-r -i -w -c --tsv -x`; live also reports in/out |
| Tests | `tests/unit/test_*.c` | 12 binaries, 264 assertions |
| Harness | `fuzz/fuzz_decode.c`, `scripts/fuzz-seeds.sh` | libFuzzer over `nt_decode_frame` |

Run: `make BUILD=asan all`, `make test`, `make fixtures`, `scripts/diff-oracle.sh fixtures/basic.pcap`.

## Oracle comparison

`scripts/diff-oracle.sh` diffs `scripts/tshark-fields.sh` (25 columns) against `sniff -r ... --tsv`.

```
scripts/diff-oracle.sh fixtures/basic.pcap -> PASS 14 packets match tshark
scripts/diff-oracle.sh fixtures/ipv6.pcap  -> PASS 5 packets match tshark
```

Explained difference: tshark dissects L4 only on the **last** IPv4 fragment; this decoder dissects
when `frag_off == 0` (the first fragment), because that is where the L4 header physically lives. The
diff script blanks columns 17-25 on both sides for any fragment row (col 11 `True` or col 12 != 0),
so the comparison stays exact everywhere else.

`malformed.pcap` (all 9 frames, expected statuses from the M0 map):

```
packets=9  truncated=5 malformed=3 unsupported=0      exit 0, no sanitizer report
```

## Hardening

- `make test` (ASan+UBSan): 12/12 test binaries, 264/264 assertions.
- `make san-test`: proves the sanitizers fire on the smoke target.
- pcap reader rejects: bad magic, short global header, non-Ethernet link type, `caplen > snaplen`,
  `caplen > 262144`, `caplen` past the file, short record header (each with its own message).
- Round trip: `sniff -r fixtures/basic.pcap -w /tmp/rt.pcap` then `cmp fixtures/basic.pcap
  /tmp/rt.pcap` -> **IDENTICAL** (byte-for-byte, timestamps preserved); tshark reads it back.
- Fuzz: `make fuzz` + `make fuzz-seeds` (28 seeds from all fixtures). **BLOCKED on this machine:
  clang is not installed** (`command -v clang` empty). Owner: install clang, then
  `make fuzz-run`; success = `-max_total_time=300` ends with no crash and no sanitizer finding.

## Break and debug (owner runs in the lab)

Experiment: checksum artifact from offloads (M9 predict-before-you-run).

```bash
NT_OFFLOAD=1 sudo -E lab/up.sh basic --force      # offloads left ON on purpose
sudo lab/ex h2 python3 -m http.server 8080 &
sudo lab/ex h1 curl -s http://10.0.2.2:8080/ >/dev/null
sudo lab/cap.sh h1 eth0 tcp                          # capture on the sending side
sudo lab/cap.sh rtr r2 tcp                           # capture after the router
sudo lab/down.sh && sudo lab/up.sh basic --force     # rebuild with offloads OFF
```

- Prediction before running: the checksum bytes on frames captured **before they leave h1** will not
  match a recomputation, because the NIC computes them; packets captured at `rtr r2` (after h1's NIC)
  will have correct checksums. TCP offload (TSO/GSO) can also make captured frames exceed the veth MTU.
- Observed: _owner to fill in_ (tool reads checksums as data; it does not treat them as errors).
- What it teaches: capture point matters; a "bad checksum" in a local capture is usually an offload
  artifact, not corruption. `lab/lib.sh:nt_tune_if` turns offloads off by default for exactly this.

## Security note

- **Attack surface**: every byte handed to `nt_decode_frame` (pcap file or live frame) is untrusted.
  All reads go through `need()`/`rd*`; wire lengths are validated against both the buffer and layer
  minima; there is no struct overlay and no integer overflow in bounds checks. The library does no
  I/O, no allocation, no globals.
- **Capture tool**: the pcap reader never allocates from a wire value (fixed `NT_SNAP` buffer,
  caplen capped). `-w` writes link type 1 only. Live capture opens `AF_PACKET` and then drops from
  root to `SUDO_UID` (or the real uid) keeping only `CAP_NET_RAW`; verify with
  `grep Cap /proc/<pid>/status` (see `scripts/lab-validation.sh`). No setuid binaries.
- **Namespaces**: all active traffic stays in `nt-*`; scripts are prefix-scoped.
- **Remaining**: no filter/BPF, so the sniffer captures all traffic on the interface; DNS
  compression-pointer loops are not reached this phase (DNS is Phase 5); pcapng and non-Ethernet
  link types are refused rather than decoded.

## Later list

- IPv6 extension-header chains; IPv4/IPv6 reassembly.
- BPF filter (`-f`) and a pcapng reader.
- Display TCP/UDP/ICMP checksum state and timestamps in `--tsv` (extra columns).
- Non-Ethernet link types (`DLT_LINUX_SLL`, `DLT_RAW`).
- `-w` from live with nanosecond timestamps and a ring buffer (`TPACKET_V3`).

## Definition-of-done status

| Item | Status |
|---|---|
| `make BUILD=asan test`, `make san-test` green, zero warnings | done |
| `--tsv` matches tshark on basic + ipv6 | done (fragments explained) |
| malformed.pcap per M0 map, no crash | done |
| pcap round trip byte-identical | done |
| fuzz 5 minutes clean | blocked: clang missing (owner to install + `make fuzz-run`) |
| live capture matches tcpdump on the lab | done: `docs/phase1-evidence/` (19 packets, live `--tsv` == tshark) |
| capabilities dropped after socket open | code + `scripts/lab-validation.sh` prints `CapEff` |
| break-and-debug + security note | security note done; break-and-debug owner to run |


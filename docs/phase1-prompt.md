## Kickoff block (paste this)

```
PHASE: 1, decode library, pcap reader/writer, AF_PACKET sniffer
MODE: MENTOR (guided, milestone-gated; protocol:  "Guided session protocol" in docs/phase1-prompt.md)
OWNER-OWNED CODE: everything in src/lib/ (all decoders, checksum, bounds helpers), the capture and
                  output logic in src/sniff/ (a minimal --tsv printer lands in M1 so M2/M3 can use the oracle)
AGENT MAY WRITE: one-page spec with byte-offset tables, unit-test cases and the test harness, fuzz
                 harness body, scripts/diff-oracle.sh, Makefile `test` target, docs. Never the decoders.
GOAL: decode Ethernet, 802.1Q, ARP, IPv4, IPv6 (fixed header), TCP, UDP, ICMP, ICMPv6 from fixtures,
      pcap files, and live capture; output matches tshark on fixtures/basic.pcap
TOPOLOGY: basic (live capture), bridge3 (ARP broadcast visibility)
ORACLES: scripts/tshark-fields.sh vs sniffer --tsv output (incl. IPv6/ICMPv6 columns); tcpdump -e;
         scapy-crafted frames
OUT OF SCOPE: IPv6 extension header chains, IP reassembly, DNS decoding (Phase 5), BPF filters (Phase 11),
              TLS, pcapng, packet injection
DONE WHEN: milestones M0-M10 below are all signed off by me
FIRST DELIVERABLE: M0 spec only. Then stop and wait for my "go".
Read AGENTS.md, README.md and docs/phase1-prompt.md first. Restate the plan in under 10 lines and wait.
```

---

## Prerequisites (before M1)

- `python3-scapy` for fixtures, M4 hand-built frames, and M9 — verify `python3 -c 'import scapy'`.
- `clang` only for M8 (`make fuzz`). Both are missing on the current machine; see `lab/deps.sh`.

---

## Guided session protocol (the agent follows this for every milestone)

1. **Brief** (max 15 lines): the wire format as an offset/size/field/notes table, RFC section numbers,
   and the two or three gotchas that bite at this layer.
2. **Predict**: ask exactly one "predict before you run" question the owner answers before any code.
3. **Tests first**: write the unit tests (hand-built byte arrays and expected results, including
   hostile ones). Owner must see them fail before implementing. The agent never writes the decoder.
4. **Owner implements.** The agent answers questions with hints, RFC pointers, and diagrams, not code.
   If the owner asks for code, ask once: "switch to IMPLEMENT for this function?" and wait for yes.
5. **Review** the owner's diff by severity (memory safety first, then correctness, then style) with
   file:line. No rewrites unless asked.
6. **Gate**: run `make BUILD=asan test`, report real output, then ask: "Sign off M<N>?" Do not start
   the next milestone until the owner says go.

Keep replies concise. Do not pad with background the owner already knows.

---

## Phase 1 hard rules

**Library (`src/lib/`)**
1. No I/O, no `printf`, no `malloc`, no globals, no `static` mutable state. Formatting lives in the tool.
2. Every decoder has the shape `nt_status f(const uint8_t *buf, size_t len, struct out *o)` and
   returns one of: `NT_OK`, `NT_ERR_TRUNCATED`, `NT_ERR_MALFORMED`, `NT_ERR_UNSUPPORTED`. Distinct
   statuses are tested separately; "any error" is not good enough.
3. Output structs hold host-order values and copy addresses into fixed arrays. Payload is a non-owning
   `(const uint8_t *, size_t)` pointing into the input; document the lifetime.
4. All reads go through bounds-checked helpers (`rd8`, `rd16be`, `rd32be`, `need(len, off, n)`).
   `need` must be overflow-safe: check `off <= len` first, then `n <= len - off`. Never compute
   `off + n` unchecked.
5. No struct overlays on the buffer, no alignment assumptions, no host-endian shortcuts.
6. Wire-supplied lengths are validated against the buffer **and** against the layer minimum:
   IHL >= 5, total length >= IHL*4, TCP data offset >= 5 and within the segment, option length byte >= 2,
   UDP length >= 8, DNS-style loops bounded (any pointer or option walk has a hard iteration cap).
7.  Bound the L3 payload by the IP total length (IPv4) or payload length (IPv6), **not** the frame length.
   Ethernet pads short frames to 60 bytes; trailing padding must not leak into L4. For IPv4: `totlen > len`
   is `NT_ERR_TRUNCATED`, `totlen < IHL*4` is `NT_ERR_MALFORMED`.
8. Fragments: decode the IP header and set a `is_fragment` flag. Parse L4 only when fragment offset is 0;
   otherwise stop at L3 with `NT_OK`. Document this choice. No reassembly.
9. Checksum code exists once (`nt_csum_*`): one's-complement add, fold, IPv4 header, ICMP, TCP/UDP with
   IPv4 and IPv6 pseudo-headers. Test with RFC 1071 vectors and fixture packets. IPv4 UDP checksum 0
   means "not computed".
10. Checksum verification reports a tri-state: `valid`, `invalid`, `not-checked`. A bad checksum is data
    to display, not a decode error.
11. EtherType below 0x0600 is a length field (802.3); return `NT_ERR_UNSUPPORTED` and test it. Allow at
    most two stacked VLAN tags (802.1Q and 802.1ad), then stop.
12. TCP options are walked, not overlaid: EOL and NOP are single bytes, everything else is
    kind/length/data; decode MSS, window scale, SACK-permitted, timestamps, ignore the rest by length.

**Tool (`src/sniff/`)**
13. CLI: `-i <if>` live, `-r <file>` pcap, `-w <file>` write pcap, `-c <n>` count, `--tsv`, `-x` hex dump
    with a field-offset annotation. Exactly one of `-i` / `-r`.
14. `--tsv` columns and order are identical to `scripts/tshark-fields.sh`. Empty field for N/A.
    Anything else is a bug in the sniffer or an explained difference recorded in `docs/phase1.md`.
15. pcap reader: classic libpcap only, both byte orders, microsecond and nanosecond magics, link type 1
    only. Reject `caplen > snaplen`, `caplen > 262144` (the libpcap default max snaplen), `caplen >
    remaining file bytes`, and a short record header, each with its own error message. Never allocate
    based on an unchecked wire value. The `-w` writer emits link type 1 (Ethernet) only; a live or file
    link type that is not Ethernet (`DLT_LINUX_SLL` from `any`, for example) returns `NT_ERR_UNSUPPORTED`
    rather than mis-decoding.
16. Live capture: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`, bind by `ifindex`, receive with
    `recvfrom` and a buffer of at least the interface MTU plus headers. Use `PACKET_AUXDATA` to recover
    VLAN tags (the kernel strips them from the frame; see gotchas). Report `PACKET_OUTGOING` vs
    incoming. Handle `EINTR`; exit cleanly on SIGINT/SIGTERM and print stats (packets, decode errors by
    status).
17. Privileges: only opening the socket needs `CAP_NET_RAW`. After opening, drop all capabilities
    (`capset` or `prctl`) before touching any untrusted data. Owner decides the mechanism; the agent
    reviews it. No `setuid` binaries.
18. A decode error never aborts the capture. Count it, print it with its status in verbose mode, move on.

**Process**
19. Default build is `BUILD=asan`. Zero warnings. The sanitizers stay on during development; `release`
    is built only at the end to confirm it still runs.
20. Every milestone adds hostile test cases next to the happy-path ones. Each `fixtures/malformed.pcap`
    frame must produce its expected status from the M0 mapping (frame 9 is `NT_OK` at UDP) with zero crashes.
21. No new dependencies. No libpcap. No protocol-header structs for decoding (`<netinet/ip.h>`,
    `<netinet/tcp.h>`, ...). Constants such as `ETH_P_*` from `<linux/if_ether.h>` are fine, as are
    kernel socket structs (`sockaddr_ll`, `tpacket_auxdata` from `<linux/if_packet.h>`).
22. Every claim of success comes with the command and its real output. If something needs root, give the
    exact command and the result that confirms it.
23. Stay in scope. Ideas outside the phase go on a "later" list in `docs/phase1.md`, not into code.
24. Unit tests live in `tests/unit/`, never under `src/` (the Makefile auto-discovers `src/*/` as tools).
    `make test` builds with `BUILD=asan` and runs them; add the `test` target using `>` recipes.

---

## Milestones (each ends with the gate from the protocol)

| # | Deliverable | Owner implements | Agent provides | Predict-before-you-run | Sign-off test |
|---|---|---|---|---|---|
| M0 | Spec | nothing | one-page spec: layer tables with offsets, status codes, API signatures incl. `nt_decode_frame` dispatcher/result, test plan | Which bytes of a 60-byte frame carrying a 28-byte IP packet are padding? | owner approves spec |
| M1 | Ethernet and VLAN | `nt_eth_decode`, bounds helpers, tool skeleton + minimal `--tsv` | tests incl. runt frame, 802.3 length, double tag; `make test` harness | Does `tcpdump -e` show the VLAN tag on a veth? Why or why not? | unit tests green, ASan clean, `--tsv` emits Ethernet/VLAN columns |
| M2 | ARP and IPv4 | `nt_arp_decode`, `nt_ipv4_decode`, IPv4 header checksum | tests incl. IHL 4 and 15, total length above and below frame, fragments, padded frame | What does the TTL field look like at `r1` vs `r2` for the same ping? | `--tsv` IPv4 rows match tshark on `basic.pcap`; malformed IHL/length cases rejected |
| M3 | TCP, UDP, ICMP | L4 decoders, options walk, pseudo-header checksums | tests incl. data offset 1 and 15, option length 0 and 1, UDP length 7 | Which SYN options appear and in what order for a Linux client? | `--tsv` L4 columns match tshark on `basic.pcap` |
| M4 | IPv6 and ICMPv6 | fixed header, next-header dispatch, ICMPv6 type/code + target address (no ND options) | hand-built scapy frames for NDP (type/code + target only) and echo | What are the ICMPv6 types for neighbor solicitation and advertisement and why does ARP not exist here? | `--tsv` IPv6/ICMPv6 rows match tshark; extension headers return `UNSUPPORTED` |
| M5 | Output and oracle diff | complete `--tsv` (L3/L4), `-x` hex annotation, oracle diff wiring | `scripts/diff-oracle.sh` | Which fields will differ for fragments and why? | `diff` against tshark empty or every difference explained |
| M6 | pcap reader/writer | both | tests with truncated file, wrong magic, huge caplen, byte-swapped file | What does a byte-swapped magic look like in `xxd`? | round trip: read `basic.pcap`, write, `cmp` equivalent, tshark reads it |
| M7 | Live capture | AF_PACKET loop, auxdata, signals, privilege drop | scenario script (lab up, traffic generators) | Will h1 pinging h2 show up twice on `rtr` capture of `any` and why? | live `--tsv` on `rtr r1` equals tcpdump for 50 packets |
| M8 | Hardening | fixes only | real `fuzz_decode.c` body calling `nt_decode_frame`, seed corpus script | Which decoder will the fuzzer break first? | 5 minute fuzz run clean, `malformed.pcap` per M0 mapping, ASan/UBSan clean |
| M9 | Lab validation | none (run experiments) | experiment script: ping, curl, DNS query, ARP flush, VLAN frame via scapy | With `NT_OFFLOAD=1`, which checksums will your tool call invalid? | offload experiment documented with captures; tool output agrees with `tcpdump -vv` |
| M10 | Write-up | `docs/phase1.md` | review against `docs/phase-template.md` | none | break-and-debug, security note, oracle result, later-list all present |

---

## Gotchas cheat sheet (the agent raises each one at the milestone it belongs to, not before)

- **Padding**: frames under 60 bytes carry trailing zeros after the IP packet. Use IP total length.
- **VLAN on AF_PACKET**: the kernel moves the tag into `PACKET_AUXDATA` (`tp_vlan_tci`, `tp_vlan_tpid`)
  for incoming frames, so the raw bytes you read have no 802.1Q header. A tag shows up in `-r` pcaps
  from `tcpdump` only if it was in-band.
- **Duplicates**: `ETH_P_ALL` sees both directions; `sockaddr_ll.sll_pkttype == PACKET_OUTGOING` marks
  frames the host sent. On `any` or bridged paths the same packet can appear more than once.
- **Offloads**: outgoing checksums can be partial, giant frames can exceed MTU (GSO/GRO). The lab disables
  offloads by default; `NT_OFFLOAD=1` brings the artifact back on purpose.
- **Pseudo-header**: TCP/UDP length is IP total length minus IHL*4, not the frame length. IPv6 pseudo-header
  differs and ICMPv6 uses it too, ICMPv4 does not.
- **TCP flags**: 9 flag bits including NS live across the data-offset byte; do not forget CWR/ECE.
- **Endianness**: pcap headers are in the writer's byte order; packets are always network order.
- **IP flags/offset**: 3 flag bits plus 13-bit offset in 8-byte units; MF with offset 0 is the first
  fragment, not "not a fragment".
- **Loopback and `any`**: link types differ (`DLT_LINUX_SLL`); this phase supports Ethernet only and must
  say so clearly rather than mis-decode.

---

## Definition of done (all must be true)

- [ ] M0-M10 each signed off in the conversation
- [ ] `make BUILD=asan test` and `make san-test` green, zero warnings
- [ ] `make fuzz` run for 5 minutes with no findings, corpus saved under `fuzz/corpus/`
- [ ] sniffer `--tsv` matches `scripts/tshark-fields.sh` on `fixtures/basic.pcap` (differences explained)
- [ ] `malformed.pcap`: every frame yields its expected status from the M0 mapping (frame 9 = `NT_OK`), no crash
- [ ] live capture on the `basic` lab matches tcpdump for a ping, a TCP connection, and a DNS query
- [ ] capabilities dropped after socket open, verified with `grep Cap /proc/<pid>/status`
- [ ] break-and-debug write-up and security note in `docs/phase1.md`
- [ ] time spent within the 1-2 week box; overruns noted with the cause

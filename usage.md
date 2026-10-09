# Usage: getting to Phase 0 done

Working order, exact commands, acceptance criteria. Run everything from the repo root
(`nettk/`). Root is needed for the lab only.

## 1. Dependencies

```bash
lab/deps.sh                     # must print "all required tools present"
```

Missing anything? On Debian/Ubuntu: `sudo lab/deps.sh --install`, or install only what it
reports. `clang` is optional — only `make fuzz` needs it and fuzz is not part of Phase 0.

## 2. Acceptance run

```bash
make phase0 2>&1 | tee docs/phase0-evidence/phase0-run.txt
```

Expected, in order:

| Output | From |
|---|---|
| `ok: --asan-test tripped (AddressSanitizer)`, `ok: --ubsan-test tripped (runtime error)` | `make san-test` |
| `wrote fixtures/basic.pcap and fixtures/malformed.pcap` | `make fixtures` |
| `lab 'basic' is up.` + hint block | `make lab-up` |
| `passed=8 failed=0 skipped=0` | `make lab-check` |

If `lab-check` fails: `lab/status.sh` first, then capture on `r1`/`r2`.

## 3. Experiments (`docs/phase0.md` 1-5)

Do each one, save command output or hex dumps (text) into `docs/phase0-evidence/`.
Pcaps stay out of git — point at the filename and the offsets you found.

1. **TTL byte by hand.** Two shells:

   ```bash
   sudo lab/cap.sh rtr r1 icmp          # shell 1
   sudo lab/ex h1 ping -c1 10.0.2.2     # shell 2
   tcpdump -nXX -r captures/<file>      # TTL at offset 14+8 = 22
   ```

   Repeat the capture on `r2`, confirm TTL dropped by one. Record offsets of dst MAC,
   src MAC, EtherType, IP protocol, src/dst IP.

2. **ARP life cycle.** `sudo lab/ex h1 ip neigh flush all`, capture on `h1 eth0`, ping
   `10.0.1.1`. Identify broadcast request, unicast reply, and `ip neigh` states
   (`REACHABLE` -> `STALE`). Why does MAC octet `02` mean locally administered?

3. **Broadcast domain.** `sudo lab/up.sh bridge3 --force`, capture on `h3 eth0`, ping
   h1->h2. h3 sees the ARP broadcast but not the unicast ICMP. Confirm with
   `sudo lab/ex sw bridge fdb show br br0`.

4. **Offload artifact.** `NT_OFFLOAD=1 sudo -E lab/up.sh basic --force`, capture on
   `h1 eth0` while h2 serves HTTP and h1 curls it. Find the bad checksums, match them to
   `ethtool -k eth0` features, rebuild with offloads off, watch them disappear.

5. **Sanitizers.** Run `build/asan/bin/smoke --asan-test` and `--ubsan-test` by hand and
   read the reports: which line, which allocation, how far past the end. Then
   `make BUILD=release all` and run the release `smoke --asan-test` — the overflow is
   silent. That is the point of the default `BUILD=asan`.

## 4. Break and debug — write up two

Pick two from the table in `docs/phase0.md`. **Predict the symptom before you run it.**

```bash
sudo lab/ex rtr sysctl -w net.ipv4.ip_forward=0     # h1 reaches rtr, not h2
sudo lab/ex h1 ip route replace default via 10.0.1.99   # unanswered ARP for .99
sudo lab/up.sh basic --force                        # restore
```

Write-ups go in `docs/phase0-evidence/` using `docs/phase-template.md`.

## 5. Security note

Five lines, per `docs/phase0.md`: which capability you keep after opening `AF_PACKET`
and which you drop; why namespace isolation is not privilege isolation; why `lab/down.sh`
must only ever match `NT_PREFIX`.

## 6. Done when

- [ ] `make phase0` passes end to end, output saved
- [ ] experiments 1-5 evidenced in `docs/phase0-evidence/`
- [ ] two break-and-debug write-ups
- [ ] security note
- [ ] `sudo lab/down.sh && make phase0` cold, under a minute, without notes

## 7. Phase 1: decode library + AF_PACKET sniffer

Orchestration and evidence: `docs/phase1.md`. No root for anything below except live capture.

### Build and decode tests

```bash
make BUILD=asan all                         # zero warnings
make test                                   # 12 test binaries, ASan+UBSan
scripts/diff-oracle.sh fixtures/basic.pcap  # sniff --tsv vs tshark: PASS 14
scripts/diff-oracle.sh fixtures/ipv6.pcap   # PASS 5
```

`sniff` CLI (exactly one of `-r`/`-i`):

```bash
build/asan/bin/sniff -r <file> [--tsv] [-x] [-c N]   # decode a capture
build/asan/bin/sniff -i <if>   [--tsv] [-x] [-c N]   # live capture (root)
build/asan/bin/sniff -r <in> -w <out>                # faithful pcap copy
build/asan/bin/sniff -i <if> -w <out>                # live capture to pcap
```

- `--tsv` is 25 columns matching `scripts/tshark-fields.sh` exactly (fragments explained in
  `docs/phase1.md`).
- `-x` is a hex dump with per-field offset annotations (`eth`, `ipv4`/`ipv6`, `tcp`/`udp`, `icmp`).
- `malformed.pcap` decodes without crashing: `packets=9 truncated=5 malformed=3`.

### pcap round trip (byte-identical)

```bash
build/asan/bin/sniff -r fixtures/basic.pcap -w /tmp/rt.pcap
cmp fixtures/basic.pcap /tmp/rt.pcap   # IDENTICAL; tshark -r /tmp/rt.pcap works
```

### Live capture in the lab

Live needs root only to open `AF_PACKET`; the process then drops to your user keeping only
`CAP_NET_RAW` (verify with `grep Cap /proc/<pid>/status`).

```bash
make lab-up
# capture on the router's h1-facing port while traffic flows:
sudo ip netns exec nt-rtr build/asan/bin/sniff -i r1 --tsv -c 10 -w /tmp/live.pcap
```

One-shot validation (captures ping/TCP/DNS, diffs live `--tsv` against tshark, shows `CapEff`):

```bash
sudo scripts/lab-validation.sh          # or: sudo scripts/lab-validation.sh 80
```

### Fuzz (needs clang)

```bash
make fuzz-seeds                         # 28 seeds extracted from fixtures/*.pcap
make fuzz-run                           # build + 5 minutes of libFuzzer
```

If `clang` is missing, `make fuzz` stops with `clang required for libFuzzer`; install `clang` first.

## 8. Done when (Phase 1)

- [ ] `make test`, `make san-test` green, zero warnings
- [ ] `scripts/diff-oracle.sh` PASS on `basic.pcap` and `ipv6.pcap`
- [ ] `malformed.pcap` per the M0 mapping, no sanitizer report
- [ ] pcap round trip `cmp` identical
- [ ] `make fuzz-run` clean for 5 minutes (needs clang)
- [ ] `sudo scripts/lab-validation.sh` PASS; `CapEff` shows only `cap_net_raw`
- [ ] break-and-debug write-up and security note in `docs/phase1.md`

## Knobs and safety

`NT_OFFLOAD`, `NT_IPV6`, `NT_PREFIX`, `BUILD` — see the table in `README.md`.
Everything active runs inside `nt-*` namespaces only, never against a real network.

## Next

Phase 2 kickoff from `AGENTS.md` (socket tooling), once M0-M10 are signed off per
`docs/phase1-prompt.md`.


# nettk: Linux networking toolkit

A progressive set of low-level networking tools (C first, Rust later) built on top of a
disposable network-namespace lab. Phase 0 is the harness; see `docs/phase0.md`.
Step-by-step commands and acceptance criteria: `usage.md`.

## Quick start (Linux, root for the lab only)

```
make deps                 # check tools; lab/deps.sh --install on Debian/Ubuntu
make phase0               # sanitizer proof, fixtures, lab up, lab checks
sudo lab/ex h1 ping -c2 10.0.2.2
sudo lab/cap.sh rtr r1 icmp          # pcap lands in captures/
make lab-down
```

Needs a real Linux kernel with namespaces (VM, bare metal, or WSL2). Containers need `--privileged`.

## Layout

| Path | Purpose |
|---|---|
| `lab/` | namespace lab: `up.sh`, `down.sh`, `status.sh`, `check.sh`, `cap.sh`, `ex`, topologies in `lab/topo/` |
| `src/lib/` | decode library (pure functions over `(const uint8_t *buf, size_t len)`, no I/O). Built into `libnettk.a` |
| `src/<tool>/` | one directory per tool, one binary per directory (`src/smoke/` exists now) |
| `fuzz/` | libFuzzer harnesses (`make fuzz`, needs clang) |
| `py/` | scapy fixture generation and traffic crafting |
| `scripts/` | oracle helpers (`tshark-fields.sh`) |
| `fixtures/`, `captures/` | generated pcaps (git-ignored) |
| `tests/` | build and sanitizer checks |
| `docs/` | phase notes, write-up template |
| `AGENTS.md` | working agreement for the coding agent |

## Topologies

- `basic`: h1 -- rtr -- h2, two routed /24s (10.0.1.0/24, 10.0.2.0/24). MACs `02:00:00:00:<net>:<host>`.
- `bridge3`: h1, h2, h3 on one bridged segment 10.0.0.0/24 for ARP, DHCP, and broadcast experiments.

Add a topology by dropping `lab/topo/<name>.sh` defining `topo_up` and `topo_hint`.

## Knobs

| Variable | Default | Effect |
|---|---|---|
| `NT_OFFLOAD` | `0` | `1` keeps NIC offloads so you can study bad-checksum artifacts |
| `NT_IPV6` | `1` | `0` disables IPv6 in namespaces for quieter captures |
| `NT_PREFIX` | `nt-` | namespace name prefix; `down.sh` only touches this prefix |
| `BUILD` | `asan` | `asan`, `tsan`, or `release` |

## Build

`make` lists targets. `make BUILD=asan` is the default and builds with ASan+UBSan.
`make san-test` proves the sanitizers actually fire. `make BUILD=release` adds FORTIFY, stack
protector, PIE, and full RELRO.

## Safety

Everything active (scanning, ARP, DHCP, forwarding) runs inside `nt-*` namespaces only.
Never point these tools at a real network.

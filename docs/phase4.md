# Phase 4, sub-phase 4: sockets (`ncx`, `echod`, `sniff --tcp-trace`)

Status: **implemented (M1–M8), sanitizer-clean, oracle-compared**. Live-lab experiments
(TIME_WAIT, queue overflow, RST variants, Nagle timing) are scripted but need root/namespaces
(`lab/scenarios-sockets.sh`) — see §7 for the exact commands and the expected results.

Scope: `src/ncx/`, `src/echod/`, `src/common/tcp_trace.{c,h}` and the `--tcp-trace` printer in
`src/sniff/`. C11, no dependencies, sockets only (`socket`, `poll`, `epoll`, `signalfd`, `timerfd`).

Extends `AGENTS.md` and `docs/phase4-6-prompt.md`. Where they conflict, the `AGENTS.md` safety rules win.
Sections 1–6 below are the canonical spec; sections 7–12 record what was built, verified, and left for the lab.

## 1. Safety envelope

- Every tool runs only inside `nt-*` via `lab/ex` and calls a guard before any socket use. Allowed peers:
  `10.0.0.0/16`, the lab IPv6 range (`fd00::/8`, `2001:db8::/32`), and loopback inside the namespace.
- Servers (`echod`) refuse to start without `--bind <address>`; the address must pass the bind guard
  (wildcard, lab range, or loopback) and the port must be ≥ 1024 (`nt_guard_server_port`).
- No tool executes anything: no `system`, `popen`, `exec*`; `ncx` has **no `-e`/`-c` option**.
- Addresses are numeric only (`inet_pton`). Libc name resolution is never called; names go through `dnsq`
  (sub-phase 5) and only inside the lab.
- Ports are 1024 or higher: no capabilities needed. `prctl(PR_SET_NO_NEW_PRIVS, 1)` at startup. Everything a
  server receives is untreated remote data (echo servers are their own HazMat — see §10).

## 2. `ncx` behavior table (implemented)

| Aspect | Rule |
|---|---|
| Modes | connect (default): `ncx [opts] HOST PORT` · listen: `ncx -l [-p PORT]` |
| Transport | TCP default; `-u` UDP |
| UDP shape | unconnected send/recv by default; `-l` binds and waits for one datagram peer, then `connect()`s to it |
| Family | `-4` default, `-6` explicit |
| `-s ADDR` | bind source address (numeric, guard-checked) |
| `-p PORT` | source port (connect) / listen port (listen); `-l` without `-p` binds port 0 and prints the real port |
| `-w SEC` | absolute connect/read deadline, monotonic clock via `poll` |
| `-N` | on stdin EOF: `shutdown(SHUT_WR)` **after** the already-read bytes are flushed to the socket; keep reading until the peer closes |
| `-v` | per-direction byte counters and close cause on exit |
| EOF default | stdin EOF → **keep the socket open**, drop `POLLIN` on fd 0, keep piping socket→stdout until the peer closes |
| EPIPE/ECONNRESET | stop writing, drain the read side if possible, exit 3 |
| SIGPIPE | ignored; UDP sends use `MSG_NOSIGNAL` |
| `--linger0` | `SO_LINGER{1,0}` before the final `close()` (exit path sends RST) |
| `--nodelay` / `--quickack` / `--cork` | applied to the connected/socket pair |

**Exit codes (all verified, §7):** `0` ok · `1` usage/bind/guard · `2` connect error · `3` write error
(EPIPE/ECONNRESET/ICMP) · `4` timeout · `5` peer closed before any data was exchanged.

**I/O discipline:** every fd is created `CLOEXEC`; `EINTR` retried; `EAGAIN` told apart from a real error;
short reads/writes handled; TCP is pumped with *bounded* 64K buffers in both directions (a full buffer stops
the corresponding poll interest — the only backpressure mechanism; buffers never grow, the loop never blocks).

## 3. `echod` architecture (implemented)

- Single-threaded **epoll**, nonblocking sockets, `accept4(SOCK_NONBLOCK|SOCK_CLOEXEC)`. **Level-triggered
  default**; `--et` sets `EPOLLET` on the listener and every conn (reads and the accept loop drain to `EAGAIN`).
- **Connection slab:** fixed array of `--max-conns` (default 1024) allocated once at startup, free list,
  no per-connection `malloc`.
- **Per-connection state:**

  | Field | Meaning |
  |---|---|
  | `fd` | accepted socket |
  | `state` | `FREE`, `HANDLING`, `CLOSING` |
  | `rbuf[64K]`, `rlen` | receive staging; while `rlen>0` the peer sees backpressure |
  | `wbuf[64K]`, `wlen`, `woff` | pending echo output |
  | `last_activity_ns`, `shutdown_sent` | drive the idle timer and the half-close sequence |
  | `bytes_in`, `bytes_out` | per-conn counters folded into global stats on close |

- **Event flow:** `EPOLLIN` read burst → move received bytes into the output queue (`evac`) → re-arm.
  Buffer full → drop `EPOLLIN`, arm `EPOLLOUT` (never grow, never block, never drop silently). `EPOLLOUT`
  write burst → drain → re-arm `EPOLLIN`.
- **Half-close:** peer FIN → state `CLOSING` → flush output → `shutdown(SHUT_WR)` → keep `EPOLLIN` until the
  peer's FIN or the idle timeout. Closing with unread received data makes the kernel send RST (documented, §9).
- **Idle timeout:** `timerfd`, default 30 s, `--idle SEC` for tests; reaps every non-FREE conn whose
  `last_activity` is older than the limit (this also closes `CLOSING` conns whose peer never sends FIN).
- **At-capacity policy:** with `--max-conns` reached, default **accept-and-close** (new client gets a prompt
  EOF instead of stalling); `--no-accept` **skips accept entirely** so the connection stays handshake-completed
  in the kernel accept queue (`ss -ltn` Recv-Q grows) until a slot frees. Both verified (§7).
- **`EMFILE`/`ENFILE` on accept:** spare-fd trick (close `/dev/null` spare, accept, immediately close the
  refused connection, reopen the spare) so the loop never busy-spins.
- **Shutdown:** SIGINT/SIGTERM via `signalfd` in the epoll set; stop accepting, bounded flush, close all,
  print stats (accepted; refused; closed by cause; bytes; peak; UDP counters).
- **UDP (`-u`):** 65535-byte buffer, `recvmsg`/`sendmsg` preserving the sender address, `MSG_TRUNC` checked
  (truncated datagrams are counted and **not** echoed), one datagram per unit under LT / drain under ET.

## 4. Socket-option table (the only place options are set)

| Option | Level | Applied to | Default | Implemented |
|---|---|---|---|---|
| `SO_REUSEADDR` | SOL_SOCKET | listener | **on** | yes |
| `SO_REUSEPORT` | SOL_SOCKET | listener | off | no (M6 experiment only; later) |
| `TCP_NODELAY` | IPPROTO_TCP | accepted conn / ncx socket | off | yes (`--nodelay`) |
| `TCP_QUICKACK` | IPPROTO_TCP | accepted conn / ncx socket | off | yes (`--quickack`) |
| `TCP_CORK` | IPPROTO_TCP | accepted conn / ncx socket | off | yes (`--cork`) |
| `SO_LINGER{1,0}` | SOL_SOCKET | close | off | yes (`--linger0`) |
| `SO_KEEPALIVE` + `TCP_KEEPIDLE/INTVL/CNT` | SOL_SOCKET/IPPROTO_TCP | conn | off | yes (`--keepalive`) |
| `SO_RCVBUF` / `SO_SNDBUF` | SOL_SOCKET | conn | kernel | no (later list) |
| `IPV6_V6ONLY` | IPPROTO_IPV6 | v6 listener | **on** (explicit) | yes (needs an IPv6 lab run) |
| `MSG_NOSIGNAL` | — | UDP/every send | — | yes |
| `SOCK_CLOEXEC`, `accept4(...CLOEXEC)` | — | all fds | — | yes |

## 5. Experiment list — the three views must agree

| Experiment | Tool | Kernel view | Capture |
|---|---|---|---|
| connect → accept | `ncx`/`echod` | `ss -tan` | `sniff --tcp-trace` |
| server-closes-first / TIME_WAIT | `echod` | `ss -tan state time-wait` | FIN/ACK timeline |
| RST (closed port, `--linger0`, post-close data) | `ncx` | `ss -tan` | RST segment |
| backlog + accept-queue overflow | `echod --backlog`, `--no-accept` | `ss -ltn` (Recv-Q/Send-Q), `nstat` ListenOverflows/ListenDrops | SYN burst (`hping3 -c`) |
| half-close flush | `ncx`/`echod` | `ss -tan` | FIN/ACK |
| Nagle vs delayed ACK | `echod --nodelay` | `ss -ti` | inter-segment timing |
| UDP semantics | `ncx -u` | — | ICMP port-unreach; fragment split |

`lab/scenarios-sockets.sh` runs each row with the tool output, kernel view and capture side by side.

## 6. Unit and oracle tests

- `tests/unit/test_tcp_trace.c` — 27 checks: flag string in tcpdump order, relative-seq wrap arithmetic,
  options string, truncation safety.
- `tests/unit/test_guard.c` — 51 checks (extended in this sub-phase with peer/bind/server-port predicates).
- **Oracles:** `tcpdump` (verified for `--tcp-trace` on `fixtures/basic.pcap`, §7), `python3` peer scripts
  for deterministic echo/backpressure/concurrency tests, `ss`/`nstat` for the live lab rows.
- **Peer scripts:** `py/loadgen.py` (bounded TCP/UDP load, prints its bounds), `py/slowclient.py`
  (no-read / slow-read / slow-write / idle) — used by the robustness rows and `lab/scenarios-sockets.sh`.
- `lab/learn/sockets.sh` (wizard lesson) exercises `ncx`/`echod` on the `basic` topology once binaries exist.

## 7. What was verified (with real output)

All commands below ran in this workspace (loopback only, `NT_LAB=1`, bounded by `-w`/`timeout`):

| Claim | How verified | Result |
|---|---|---|
| Build is clean | `make BUILD=asan all` | zero warnings (`-Wall -Wextra -Wpedantic -Wshadow`) |
| Unit tests | `make BUILD=asan test` | 17 binaries, all pass (462 checks incl. new `test_tcp_trace`) |
| `ncx` bidirectional relay | `printf srv-line \| ncx -l -p N` ⋄ `printf cli-line \| ncx -N HOST N` | client got `srv-line`, server got `cli-line`, both exit 0 |
| `ncx` exit codes | see cases below | 0 relay · 1 guard/usage · 2 refused · 3 RST/ICMP · 4 `-w` timeout · 5 peer-closed-before-data |
| guards | port 80 / `8.8.8.8` / missing `NT_LAB` | all refused with message, exit 1 |
| `echod` echo | `ncx -N … \| echod` | 11 bytes in/out, exit 0 |
| backpressure | 200 KB burst through 64K buffers | `204800 True`, `bytes_in=204800 bytes_out=204800` |
| concurrency | 10 × 100 KB parallel clients | `errors: none`, `peak=10`, 1,000,000 bytes in/out |
| half-close flush | repeated `ncx -N` echo | **20/20** after the `POLLHUP` fix (§8), previously ~50 % lost |
| idle reaping | `echod --idle 1 --stats`, idle client | `closed{… timeout=1 …}` |
| capacity, default | `--max-conns 1`, 2nd client | `accepted=1 refused=1`, 2nd client got prompt EOF |
| capacity, `--no-accept` | `--max-conns 1 --no-accept`, 2nd client | `accepted=1 refused=0`, 2nd client stalled in accept queue |
| UDP echo | python UDP peer | `got: b'udp-echo-msg'`, `udp{in=1 out=1 trunc=0}` |
| `--et` mode | echo under `--et` | exit 0, echo returned |
| `sniff --tcp-trace` | `fixtures/basic.pcap` vs `tcpdump -nn -r` | flags/relative-seq/ack/win/opts match (table below) |
| malformed input | `sniff -r fixtures/malformed.pcap --tcp-trace` | `truncated=5 malformed=3`, no crash |

`--tcp-trace` vs tcpdump on the same SYN/SYN-ACK/GET segments:

```
tcpdump: Flags [S],  seq 1000, win 8192, options [mss 1460,sackOK,TS val 111 ecr 0,nop,wscale 7]
sniff:   Flags [.S.......], seq 0, … options [mss=1460,sack,ts=111<0>,wscale=7], length 0
tcpdump: Flags [S.], seq 5000, ack 1001 …   → sniff: seq 0, ack 1
tcpdump: Flags [P.], seq 1:34, ack 1, length 33   → sniff: seq 1:34, ack 1, length 33
```

Differences are formatting only (fixed 9-flag mask vs tcpdump's compact `[S.]`; options reordered/deduped).

## 8. Break-and-debug write-up: the `POLLHUP` data-loss bug

Found while stress-testing the `ncx -N` ↔ `echod` echo path: the echo came back **flakily** (3/5 runs),
always with `ncx: sent=3 recv=0 cause=normal close` while `echod` reported `bytes_out=3` — the server
really did write the echo.

**Mechanism.** `poll(2)` reports `POLLIN|POLLHUP` at the same time when data and FIN coalesce into one
segment (tiny exchanges do this constantly). `ncx` tested `POLLHUP` *before* trying to read and set
`sock_eof`, so the buffered echo was never consumed and the relay exited. When the data segment arrived in a
separate event before the FIN event (`POLLIN` alone), it worked — hence the flakiness.

**Fix.** On `POLLIN|POLLHUP`, drain the socket until `EAGAIN` or EOF: `recv()` returns pending data first and
`0` for EOF, so `POLLHUP` must not shortcut the read path. `POLLERR` is still checked first via `SO_ERROR`.
After the fix: **20/20** runs echoed byte-identically.

**Lesson.** `POLLHUP` (and `EPOLLHUP`) is "no more *new* data will arrive, and the send side may be closed" —
it is orthogonal to "nothing is buffered". The same trap exists in every event loop; epoll's `EPOLLHUP` for a
socket that received FIN behaves identically.

## 9. Lab-pending (needs root + `nt-*` namespaces) — exact commands

Run `lab/scenarios-sockets.sh` (it is prefix-scoped, bounded, and prints its own bounds). Rows it covers:

1. **TIME_WAIT when the server closes first** — predict *which side* and *how long*, then
   `ss -tan state time-wait` + a `tcpdump -w` capture with `sniff --tcp-trace` on the same flow.
2. **`--linger0` RST** — `ncx -N --linger0` against `echod`, capture shows RST instead of FIN.
3. **Backlog overflow / SYN cookies** — `echod --backlog 1 --no-accept` under `py/loadgen.py --tcp N`,
   read `nstat -z ListenOverflows ListenDrops` before/after, watch `ss -ltn` Recv-Q.
4. **Nagle vs delayed ACK** — two 1-byte writes with `--nodelay` off vs on; `ss -ti` shows `nodelay`/`cubic`
   and the capture shows one vs two segments.
5. **IPv6** — `echod -6 --bind fd00::1:…` and `ncx -6 -N …`, quick echo check (`IPV6_V6ONLY` path).
6. **RST on close-with-unread-data** — send 100 KB, don't read, close the client: server's close() of the
   accepted conn with unread data aborts with RST (`ss -tan` shows no FIN handshake; capture shows R).
7. **UDP ICMP port-unreach revisited on real links** — `ncx -u` to a dead port, surfaces as exit 3.

Expected results per row are embedded as comments in the script; any difference from `ss`/`nstat`/capture must
be explained before sign-off (per AGENTS.md §5 step 5).

## 10. Security note

**Attack surface.** `echod` accepts bytes from anybody the guard lets in and echoes them verbatim; `ncx` pipes
peer bytes to stdout. Both treat all received data as untrusted. Nothing received is interpreted: no
escaping needed for sockets output, but a terminal-feeding display would need `%q`-style quoting (out of
scope; `ncx` prints raw bytes by design, like `nc`).

**Hardened in this sub-phase.** Guard predicates (`nt_guard_peer/bind/server_port`) implemented and
unit-tested before the tools were written; no exec/`-e`/`-c`; numeric-only addresses; ports ≥ 1024;
`PR_SET_NO_NEW_PRIVS`; all fds `CLOEXEC`; every syscall checked with `EINTR`/`EAGAIN` distinguished; bounded
64K buffers everywhere (no unbounded growth — the backpressure mechanism IS the cap); connection slab is
fixed-size, no per-conn malloc, free-list reuse; `recvmsg` on UDP checks `MSG_TRUNC` so truncated datagrams
are never echoed; epoll registration is by explicit fd (no pointer into the slab that could dangle after a
free — `conn_by_fd` rescans the slab by fd); ASan+UBSan run for the whole test suite and all loopback
stress tests (one real stack-overflow read was caught by ASan during development and fixed — see below).

**Found by ASan during development.** `ncx` `bind_local` initially built a `struct sockaddr_in` on the stack
and then memcpy'd it via a `sockaddr_storage*` cast — a 128-byte read of a 16-byte object. ASan reported it
immediately; the function now writes directly into the `sockaddr_storage`.

**What remains.** Host-level firewalling of the lab link (out of scope by AGENTS.md §3.2); fuzzing of pcap
inputs is separately covered by `fuzz/` for the decode library; the server's `SO_RCVBUF`/`SO_SNDBUF` knobs
and `SO_REUSEPORT` are not yet implemented (later list); `--keepalive` parameters are compile-time constants.

## 11. Files

| Path | What |
|---|---|
| `src/ncx/main.c` | `ncx` relay (~850 lines: poll pump, nonblocking connect, guards, exit codes) |
| `src/echod/main.c` | `echod` epoll server (~900 lines: slab, backpressure, half-close, timer/signal, UDP) |
| `src/common/tcp_trace.{c,h}` | flags string, relative-seq, options string shared with `sniff` |
| `src/sniff/main.c` | `--tcp-trace` flow table (256 flows) + printer |
| `tests/unit/test_tcp_trace.c` | 27 checks |
| `py/loadgen.py`, `py/slowclient.py` | bounded lab peers |
| `lab/learn/sockets.sh` | wizard lesson (skips tool steps until binaries exist) |
| `lab/scenarios-sockets.sh` | the §9 lab rows |

## 12. Predict before you run (lab question)

`echod --linger0` closes an idle accepted connection with `SO_LINGER{1,0}`. A client that is *not reading*
has 100 KB sitting in the server's receive buffer. Predict which packet the capture shows when the server
closes — FIN or RST — and then check `ss -tan` for the client-side state after the close. Run the row with
`--linger0` and without it and compare. (`docs/phase4.md` §9 keeps the TIME_WAIT question open for the first
lab run.)
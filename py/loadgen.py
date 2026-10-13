#!/usr/bin/env python3
"""Bounded TCP/UDP load generator for `echod` (Phase 4, M0 scaffolding).

Prints its exact bounds before sending anything and hard-stops at them. It is
launched inside a lab namespace via `lab/ex`, talks only to a numeric address in
the lab ranges, and never executes anything.

  sudo lab/ex h1 python3 py/loadgen.py --host 10.0.1.1 --port 9000 \
       --mode tcp --conns 8 --bytes 1048576 --concurrent 4

Every requested value is clamped to the hard bounds and the clamping is printed,
so a run can never exceed them by accident.
"""
import argparse
import hashlib
import socket
import sys
import threading
import time

# Hard bounds. Nothing in this file may send more than these.
MAX_CONNS       = 1000
MAX_THREADS     = 256
MAX_BYTES_CONN  = 64 * 1024 * 1024
MAX_BYTES_TOTAL = 256 * 1024 * 1024
MAX_WALL        = 30.0     # seconds

PATTERN = bytes(range(256))


def in_lab(host: str) -> bool:
    """Numeric-only, lab-range-only check (mirrors src/common/guard.c)."""
    try:
        ip = socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            ip = socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            return False
        if ip[0] == 0xFD or ip[:4] == bytes((0x20, 0x01, 0x0D, 0xB8)):
            return True
        return ip == bytes(15) + b"\x01"          # ::1
    v4 = int.from_bytes(ip, "big")
    return (v4 & 0xFFFF0000) == 0x0A000000 or (v4 & 0xFF000000) == 0x7F000000


def clamp(name: str, value: int, hi: int) -> int:
    if value > hi:
        print(f"  bound: {name} {value} clamped to {hi}", file=sys.stderr)
        return hi
    return value


def payload_for(n: int, chunk: int) -> bytes:
    return (PATTERN * (chunk // 256 + 1))[:chunk]


def tcp_conn(args, results, lock):
    want = args.bytes
    sent = got = 0
    h_sent = hashlib.sha256()
    h_got = hashlib.sha256()
    deadline = time.monotonic() + args.wall
    try:
        s = socket.create_connection((args.host, args.port), timeout=5.0)
    except OSError as e:
        with lock:
            results.append(("connect-error", str(e), 0, 0))
        return
    try:
        s.settimeout(max(0.5, args.wall))
        chunk = payload_for(want, 65536)
        while sent < want and time.monotonic() < deadline:
            n = min(len(chunk), want - sent)
            try:
                w = s.send(chunk[:n])
            except OSError:
                break
            if w <= 0:
                break
            h_sent.update(chunk[:w])
            sent += w
        s.shutdown(socket.SHUT_WR)             # EOF so the server can flush and finish
        while got < want and time.monotonic() < deadline:
            try:
                b = s.recv(65536)
            except OSError:
                break
            if not b:
                break
            h_got.update(b)
            got += len(b)
    finally:
        s.close()
    with lock:
        results.append(("ok" if h_sent.digest() == h_got.digest() else "mismatch",
                        "", sent, got))


def udp_run(args, results, lock):
    s = socket.socket(socket.AF_INET6 if args.family == 6 else socket.AF_INET,
                      socket.SOCK_DGRAM)
    s.settimeout(1.0)
    payload = payload_for(args.bytes, min(args.bytes, 65507))
    sent = 0
    deadline = time.monotonic() + args.wall
    for _ in range(args.conns):
        if time.monotonic() >= deadline:
            break
        try:
            s.sendto(payload, (args.host, args.port))
            sent += len(payload)
        except OSError:
            pass
    with lock:
        results.append(("udp", "", sent, 0))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="numeric lab address")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--mode", choices=("tcp", "udp"), default="tcp")
    ap.add_argument("--conns", type=int, default=1)
    ap.add_argument("--bytes", type=int, default=4096, help="bytes per connection/datagram")
    ap.add_argument("--concurrent", type=int, default=1, help="parallel TCP workers")
    ap.add_argument("--wall", type=float, default=10.0, help="wall-clock cap seconds (<=30)")
    args = ap.parse_args()

    if not in_lab(args.host):
        print(f"loadgen: refusing {args.host}: not a numeric lab address", file=sys.stderr)
        return 2

    args.conns      = clamp("conns", args.conns, MAX_CONNS)
    args.bytes      = clamp("bytes/conn", args.bytes, MAX_BYTES_CONN)
    args.concurrent = clamp("concurrent", args.concurrent, MAX_THREADS)
    args.wall       = min(args.wall, MAX_WALL)
    if args.conns * args.bytes > MAX_BYTES_TOTAL:
        args.bytes = max(1, MAX_BYTES_TOTAL // max(1, args.conns))
        print(f"  bound: total bytes capped at {MAX_BYTES_TOTAL} "
              f"(bytes/conn now {args.bytes})", file=sys.stderr)

    print(f"bounds: mode={args.mode} host={args.host}:{args.port} conns={args.conns} "
          f"bytes/conn={args.bytes} concurrent={args.concurrent} "
          f"wall<={args.wall:.1f}s total_bytes<={args.conns * args.bytes}", flush=True)

    results = []
    lock = threading.Lock()
    t0 = time.monotonic()
    if args.mode == "udp":
        udp_run(args, results, lock)
    else:
        workers = max(1, args.concurrent)
        per = args.conns // workers
        extra = args.conns % workers
        threads = []
        for w in range(workers):
            n = per + (1 if w < extra else 0)
            for _ in range(n):
                th = threading.Thread(target=tcp_conn, args=(args, results, lock))
                th.start()
                threads.append(th)
                time.sleep(0.005)              # gentle pacing, never a storm
        for th in threads:
            th.join()
    dt = time.monotonic() - t0

    sent = sum(r[2] for r in results)
    got = sum(r[3] for r in results)
    bad = [r for r in results if r[0] not in ("ok", "udp")]
    print(f"done: {len(results)} connections, sent={sent} received={got} "
          f"elapsed={dt:.2f}s", flush=True)
    for r in bad[:10]:
        print(f"  {r[0]} {r[1]} sent={r[2]} received={r[3]}", flush=True)
    if len(bad) > 10:
        print(f"  ... {len(bad) - 10} more failures", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

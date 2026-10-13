#!/usr/bin/env python3
"""Slow / abusive TCP clients for `echod` robustness tests (Phase 4, M0).

Four bounded misbehaviours, one per run, so the owner can watch server memory,
socket buffers and the event loop under a client that will not play fair:

  no-read     connect, push up to --bytes as fast as the socket accepts, never read
  slow-read   send --bytes, then read one byte every --delay s
  slow-write  send one byte every --delay s (Nagle/delayed-ACK territory)
  idle        connect, send nothing, hold the connection for --seconds

Prints its bounds before connecting and hard-stops at them. Numeric lab
addresses only; launched inside a namespace via `lab/ex`.
"""
import argparse
import socket
import sys
import time

MAX_SECONDS = 30.0
MAX_DELAY   = 5.0
MAX_BYTES   = 64 * 1024 * 1024
MAX_CONNS   = 64

PATTERN = bytes(range(256))


def in_lab(host: str) -> bool:
    try:
        ip = socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            ip = socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            return False
        return ip[0] == 0xFD or ip[:4] == bytes((0x20, 0x01, 0x0D, 0xB8)) \
            or ip == bytes(15) + b"\x01"
    v4 = int.from_bytes(ip, "big")
    return (v4 & 0xFFFF0000) == 0x0A000000 or (v4 & 0xFF000000) == 0x7F000000


def chunk(n: int) -> bytes:
    return (PATTERN * (n // 256 + 1))[:n]


def run_once(args, idx: int) -> None:
    tag = f"[{idx}]"
    try:
        s = socket.create_connection((args.host, args.port), timeout=5.0)
    except OSError as e:
        print(f"{tag} connect failed: {e}", flush=True)
        return
    s.settimeout(1.0)
    print(f"{tag} connected, mode={args.mode}", flush=True)
    t0 = time.monotonic()

    try:
        if args.mode == "idle":
            while time.monotonic() - t0 < args.seconds:
                time.sleep(0.2)
        elif args.mode == "no-read":
            want, sent, buf = args.bytes, 0, chunk(65536)
            while sent < want and time.monotonic() - t0 < args.seconds:
                try:
                    w = s.send(buf[:min(len(buf), want - sent)])
                except (BlockingIOError, socket.timeout):
                    time.sleep(0.05)
                    continue
                except OSError:
                    break
                if w <= 0:
                    break
                sent += w
            print(f"{tag} wrote {sent} bytes without reading", flush=True)
        elif args.mode == "slow-write":
            sent = 0
            while time.monotonic() - t0 < args.seconds:
                try:
                    if s.send(b"x") == 1:
                        sent += 1
                except OSError:
                    break
                time.sleep(args.delay)
            print(f"{tag} slow-wrote {sent} bytes", flush=True)
        elif args.mode == "slow-read":
            want, sent, buf = args.bytes, 0, chunk(65536)
            while sent < want:
                try:
                    sent += s.send(buf[:min(len(buf), want - sent)])
                except OSError:
                    break
            print(f"{tag} sent {sent}, now draining 1 byte every {args.delay}s", flush=True)
            got = 0
            while time.monotonic() - t0 < args.seconds:
                try:
                    b = s.recv(1)
                except (socket.timeout, BlockingIOError):
                    continue
                except OSError:
                    break
                if not b:
                    break
                got += 1
                time.sleep(args.delay)
            print(f"{tag} slow-read {got} bytes", flush=True)
    finally:
        s.close()
        print(f"{tag} closed after {time.monotonic() - t0:.1f}s", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="numeric lab address")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--mode", choices=("no-read", "slow-read", "slow-write", "idle"),
                    required=True)
    ap.add_argument("--conns", type=int, default=1, help="connections (<=64)")
    ap.add_argument("--bytes", type=int, default=1024 * 1024)
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between pokes (<=5)")
    ap.add_argument("--seconds", type=float, default=10.0, help="total run cap (<=30)")
    args = ap.parse_args()

    if not in_lab(args.host):
        print(f"slowclient: refusing {args.host}: not a numeric lab address", file=sys.stderr)
        return 2
    args.conns   = min(args.conns, MAX_CONNS)
    args.bytes   = min(args.bytes, MAX_BYTES)
    args.delay   = min(args.delay, MAX_DELAY)
    args.seconds = min(args.seconds, MAX_SECONDS)

    print(f"bounds: mode={args.mode} host={args.host}:{args.port} conns={args.conns} "
          f"bytes={args.bytes} delay={args.delay}s seconds<={args.seconds}s", flush=True)

    for i in range(args.conns):
        run_once(args, i)
    return 0


if __name__ == "__main__":
    sys.exit(main())

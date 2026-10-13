#!/usr/bin/env python3
"""udp68: a *plain* UDP socket bound to port 68 (or any port) in the lab.

This is the M20 "why a raw socket" experiment. A normal socket bound to
0.0.0.0:68 receives a DHCP reply only when the server broadcasts it (the
broadcast flag is set) or when the client already owns the unicast address;
a reply unicast to an address the client does not have yet is dropped by the
kernel (no local address to deliver it to, and the client cannot answer ARP).
dhcpc deliberately uses AF_PACKET instead, so it sees the frame regardless.

usage:
  py/udp68.py [--addr 0.0.0.0] [--port 68] [--count N] [--timeout S] [--hex]

Prints one line per datagram: source, length, and a decoded DHCP summary.
No external dependencies (stdlib only).
"""
import argparse
import socket
import struct
import sys
import time

MAGIC = b"\x63\x82\x53\x63"
MSGTYPE = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
           5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def ip4(b):
    return ".".join(str(x) for x in b)


def summarize(data):
    if len(data) < 240 or data[236:240] != MAGIC:
        return f"len={len(data)} (not DHCP)"
    op = data[0]
    yiaddr = ip4(data[16:20])
    chaddr = ":".join("%02x" % x for x in data[28:34])
    # option 53
    mtype = "?"
    i = 240
    while i < len(data):
        code = data[i]
        if code == 0:
            i += 1
            continue
        if code == 255:
            break
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        if code == 53 and ln >= 1:
            mtype = MSGTYPE.get(data[i + 2], str(data[i + 2]))
        i += 2 + ln
    return (f"op={'BOOTREQUEST' if op == 1 else 'BOOTREPLY'} "
            f"type={mtype} yiaddr={yiaddr} chaddr={chaddr}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=68)
    ap.add_argument("--count", type=int, default=1, help="number of datagrams to catch")
    ap.add_argument("--timeout", type=float, default=10.0, help="seconds per datagram")
    ap.add_argument("--hex", action="store_true", help="also hex-dump the payload")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((args.addr, args.port))
    print(f"udp68: listening on {args.addr}:{args.port} for {args.count} datagram(s)",
          flush=True)

    got = 0
    deadline = time.time() + args.timeout
    while got < args.count:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        s.settimeout(remaining)
        try:
            data, peer = s.recvfrom(65535)
        except socket.timeout:
            break
        got += 1
        print(f"[{got}] {peer[0]}:{peer[1]} len={len(data)} {summarize(data)}", flush=True)
        if args.hex:
            for off in range(0, len(data), 16):
                chunk = data[off:off + 16]
                print("    %04x  %-47s  %s" % (
                    off, " ".join("%02x" % b for b in chunk),
                    "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)),
                    flush=True)
        deadline = time.time() + args.timeout

    print(f"udp68: received {got} datagram(s)", flush=True)
    return 0 if got > 0 else 1


if __name__ == "__main__":
    sys.exit(main())

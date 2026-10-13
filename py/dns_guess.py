#!/usr/bin/env python3
"""Blind id-guess DNS "server" for the unprivileged M15 demo.

It owns a (loopback, port 5305) socket and answers an incoming query with a
*guessed* transaction id instead of the one it received. That isolates the id
half of nt_dns_match:

  * dnsq --weak  uses id 1 for the first ask, so a guess of 1 matches;
  * dnsq        uses getrandom(2) for the id, so the guess is dropped and the
                client counts `ignored` then `timeout`.

It also prints the id it actually received, so the caller can assert the
guess was wrong (not just lucky). Loopback only; it refuses any address that is
not 127.0.0.0/8 or 10.0.5.0/24.
"""
import argparse
import ipaddress
import socket
import struct


def parse_qid_and_name(buf):
    if len(buf) < 12:
        return None, None
    qid = struct.unpack(">H", buf[0:2])[0]
    off, labels = 12, []
    while off < len(buf):
        n = buf[off]
        if n == 0:
            break
        if n & 0xc0:
            labels.append("?")
            break
        off += 1
        labels.append(buf[off:off + n].decode("latin-1"))
        off += n
    return qid, ".".join(labels)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--addr", default="127.0.0.1", help="bind address (loopback)")
    ap.add_argument("--port", type=int, default=5305, help="bind port (>= 1024)")
    ap.add_argument("--guess-id", type=int, default=1, help="the id to pretend we saw")
    ap.add_argument("--answer", default="10.0.5.66", help="address in the forged answer")
    ap.add_argument("--count", type=int, default=3, help="replies to send per query")
    args = ap.parse_args()

    a = ipaddress.ip_address(args.addr)
    lab = ipaddress.ip_network("10.0.5.0/24")
    if not (a.is_loopback or a in lab):
        raise SystemExit(f"{a} is neither loopback nor {lab}: refusing (lab only)")
    if args.port < 1024:
        raise SystemExit("refusing a well-known port; use >= 1024")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.addr, args.port))
    print(f"ready: guessing id={args.guess_id} answer={args.answer} on "
          f"{args.addr}:{args.port}", flush=True)

    data, peer = s.recvfrom(4096)
    real_id, qname = parse_qid_and_name(data)
    print(f"received id=0x{real_id:04x} qname={qname} from {peer[0]}:{peer[1]}",
          flush=True)

    # echo the question back, answer A, but with the *guessed* id
    qname_enc = b""
    for lab_ in (qname or "").split("."):
        if lab_:
            qname_enc += bytes([len(lab_)]) + lab_.encode("latin-1")
    qname_enc += b"\x00"
    q = qname_enc + struct.pack(">HH", 1, 1)
    rr = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) +
          socket.inet_aton(args.answer))
    for _ in range(args.count):
        hdr = struct.pack(">HHHHHH", args.guess_id, 0x8180, 1, 1, 0, 0)
        s.sendto(hdr + q + rr, peer)
    print(f"sent {args.count} replies with guessed id=0x{args.guess_id:04x}", flush=True)


if __name__ == "__main__":
    main()

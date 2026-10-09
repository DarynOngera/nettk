#!/usr/bin/env python3
"""Correct or hostile ICMP echo responder for ping oracle tests (M2/M3).

Run it inside a lab namespace via lab/ex, on a host that owns --target. Add the
address and suppress the kernel's own echo reply so *only* this responder
answers:

  sudo ip netns exec nt-h2 ip addr add 10.0.2.99/24 dev eth0
  sudo ip netns exec nt-h2 sysctl -qw net.ipv4.icmp_echo_ignore_all=1
  sudo lab/ex h2 python3 py/responders.py eth0 --target 10.0.2.99 --mode wrong-id
  sudo lab/ex h1 build/asan/bin/ping -c2 10.0.2.99   # must accept zero replies

modes:
  correct       mirror id/seq/payload (sanity check the harness)
  wrong-id      id+1        (matcher must reject)
  wrong-seq     seq+1       (matcher must reject)
  wrong-src     a different source address (matcher must reject)
  bad-checksum  deliberate wrong checksum (matcher must reject)
  dup           send the correct reply twice (must count once per probe)
  payload       corrupt the echoed payload (matcher must reject)
"""
import argparse

from scapy.all import Ether, ICMP, IP, Raw, sendp, sniff

MODES = ["correct", "wrong-id", "wrong-seq", "wrong-src", "bad-checksum", "dup", "payload"]


def build_reply(req, args):
    ip = req[IP]
    icmp = req[ICMP]
    iid, seq = icmp.id, icmp.seq
    src = args.target
    payload = bytes(icmp.payload)

    if args.mode == "wrong-id":
        iid = (iid + 1) & 0xFFFF
    elif args.mode == "wrong-seq":
        seq = (seq + 1) & 0xFFFF
    elif args.mode == "wrong-src":
        src = args.src
    elif args.mode == "payload":
        payload = b"X" * len(payload)

    pkt = (Ether(src=req[Ether].dst, dst=req[Ether].src) /
           IP(src=src, dst=ip.src) /
           ICMP(type=0, id=iid, seq=seq) / Raw(payload))
    if args.mode == "bad-checksum":
        pkt[ICMP].chksum = 0x1234
    return pkt


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("iface", help="interface to answer on (inside the namespace)")
    ap.add_argument("--target", required=True, help="address being pinged")
    ap.add_argument("--src", default="10.0.2.99", help="source to use for wrong-src")
    ap.add_argument("--mode", default="correct", choices=MODES)
    ap.add_argument("--count", type=int, default=0, help="stop after N replies (0 = timeout only)")
    ap.add_argument("--timeout", type=int, default=30, help="sniff timeout seconds")
    args = ap.parse_args()

    seen = {"n": 0}

    def handle(req):
        pkt = build_reply(req, args)
        sendp(pkt, iface=args.iface, verbose=False)
        if args.mode == "dup":
            sendp(pkt, iface=args.iface, verbose=False)
        seen["n"] += 1
        print(f"#{seen['n']} {args.mode}: id={pkt[ICMP].id} seq={pkt[ICMP].seq} "
              f"src={pkt[IP].src} csum=0x{int(pkt[ICMP].chksum):04x}", flush=True)
        if args.count and seen["n"] >= args.count:
            raise SystemExit(0)

    sniff(iface=args.iface, filter="icmp and icmp[icmptype]==8",
          prn=handle, store=False, timeout=args.timeout)


if __name__ == "__main__":
    main()

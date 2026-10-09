#!/usr/bin/env python3
"""Correct or hostile NDP responder for the `ndp` validity checks (M9).

It answers Neighbour Solicitations for --target without owning the address, so
the kernel does not race it. Run inside a lab namespace on the same L2 as the
resolver:

  sudo lab/ex rtr python3 py/ndp_responders.py r1 --target fd00:1::99 --mode hop64
  sudo lab/ex h1 build/asan/bin/ndp -i eth0 -c1 fd00:1::99   # must report none

modes:
  correct        honest NA, hop limit 255 (sanity check the harness)
  hop64          NA with hop limit 64    (RFC 4861 7.1.1: matcher rejects)
  wrong-target   NA target != requested  (matcher rejects)
  bad-checksum   corrupt NA checksum     (matcher rejects)
"""
import argparse

from scapy.all import (Ether, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr,
                       IPv6, get_if_hwaddr, sendp, sniff)

MODES = ["correct", "hop64", "wrong-target", "bad-checksum"]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("iface", help="interface to answer on (inside the namespace)")
    ap.add_argument("--target", required=True, help="address being solicited")
    ap.add_argument("--mode", default="correct", choices=MODES)
    ap.add_argument("--count", type=int, default=0, help="stop after N replies (0 = timeout only)")
    ap.add_argument("--timeout", type=int, default=30, help="sniff timeout seconds")
    args = ap.parse_args()

    mac = get_if_hwaddr(args.iface)
    seen = {"n": 0}

    def handle(req):
        if ICMPv6ND_NS not in req:
            return
        if req[ICMPv6ND_NS].tgt != args.target:
            return
        tgt = args.target
        hlim = 255
        if args.mode == "hop64":
            hlim = 64
        elif args.mode == "wrong-target":
            tgt = req[ICMPv6ND_NS].tgt.replace("::99", "::98")

        na = (Ether(src=mac, dst=req[Ether].src) /
              IPv6(src=args.target, dst=req[IPv6].src, hlim=hlim) /
              ICMPv6ND_NA(tgt=tgt, R=0, S=1, O=1) /
              ICMPv6NDOptDstLLAddr(lladdr=mac))
        if args.mode == "bad-checksum":
            na[ICMPv6ND_NA].cksum = 0x1234
        sendp(na, iface=args.iface, verbose=False)
        seen["n"] += 1
        print(f"#{seen['n']} {args.mode}: tgt={na[ICMPv6ND_NA].tgt} hlim={hlim}", flush=True)
        if args.count and seen["n"] >= args.count:
            raise SystemExit(0)

    print("ready", flush=True)
    sniff(iface=args.iface, filter="icmp6 and icmp6[icmp6type]==135",
          prn=handle, store=False, timeout=args.timeout)


if __name__ == "__main__":
    main()

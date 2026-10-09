#!/usr/bin/env python3
"""Correct or hostile ARP responder for the `arp` validity checks (M7).

It answers ARP requests for --target without owning the address, so the kernel
does not race us with its own correct reply. Run inside a lab namespace:

  sudo lab/ex h2 python3 py/arp_responders.py eth0 --target 10.0.2.99 --mode wrong-eth-src
  sudo lab/ex h1 build/asan/bin/arp -i eth0 -c1 10.0.2.99   # must report no reply

modes:
  correct          honest reply (sanity check the harness)
  wrong-sender-ip  ARP sender protocol != target        (matcher rejects)
  wrong-eth-src    Ethernet src != ARP sender hardware  (matcher rejects)
  wrong-target     reply aimed at a different address   (matcher rejects)
  dup              send the honest reply twice          (accept exactly one)
"""
import argparse

from scapy.all import ARP, Ether, get_if_hwaddr, sendp, sniff

MODES = ["correct", "wrong-sender-ip", "wrong-eth-src", "wrong-target", "dup"]


def build_reply(req, args, mac):
    arp = req[ARP]
    eth_src = mac
    psrc = args.target
    pdst = arp.psrc
    hwdst = arp.hwsrc

    if args.mode == "wrong-sender-ip":
        psrc = args.fake_ip
    elif args.mode == "wrong-eth-src":
        eth_src = args.fake_mac
    elif args.mode == "wrong-target":
        pdst = args.fake_ip

    return (Ether(src=eth_src, dst=arp.hwsrc) /
            ARP(op=2, hwsrc=mac, psrc=psrc, hwdst=hwdst, pdst=pdst))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("iface", help="interface to answer on (inside the namespace)")
    ap.add_argument("--target", required=True, help="address being requested")
    ap.add_argument("--fake-ip", default="10.0.2.98", help="decoy address")
    ap.add_argument("--fake-mac", default="02:00:00:de:ad:be", help="decoy Ethernet src")
    ap.add_argument("--mode", default="correct", choices=MODES)
    ap.add_argument("--count", type=int, default=0, help="stop after N replies (0 = timeout only)")
    ap.add_argument("--timeout", type=int, default=30, help="sniff timeout seconds")
    args = ap.parse_args()

    mac = get_if_hwaddr(args.iface)
    seen = {"n": 0}

    def handle(req):
        if ARP not in req or req[ARP].op != 1 or req[ARP].pdst != args.target:
            return
        reply = build_reply(req, args, mac)
        sendp(reply, iface=args.iface, verbose=False)
        if args.mode == "dup":
            sendp(reply, iface=args.iface, verbose=False)
        seen["n"] += 1
        print(f"#{seen['n']} {args.mode}: psrc={reply[ARP].psrc} "
              f"eth_src={reply[Ether].src} pdst={reply[ARP].pdst}", flush=True)
        if args.count and seen["n"] >= args.count:
            raise SystemExit(0)

    print("ready", flush=True)
    sniff(iface=args.iface, filter="arp", prn=handle, store=False, timeout=args.timeout)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate golden wire vectors for the M1 builders (scapy is the oracle).

usage: py/gen_golden.py [outdir]     (default: fixtures/golden)

Each file holds one lowercase hex string. The C builders must reproduce these
byte-for-byte:
  icmp_echo.hex    ICMPv4 echo request (type 8), checksum included
  arp_request.hex  full Ethernet + ARP request, 42 bytes
  icmp6_ns.hex     ICMPv6 neighbour solicitation + source link-layer option
                   (IPv6 header stripped, so only the checksum-carrying message
                   remains; the checksum is over the IPv6 pseudo-header)
Fixed inputs keep the output reproducible.
"""
import sys
from pathlib import Path

from scapy.all import (ARP, ICMP, ICMPv6EchoRequest, ICMPv6ND_NS,
                       ICMPv6NDOptSrcLLAddr, IPv6, Ether, Raw)

H1 = "02:00:00:00:01:02"
IP1, GW = "10.0.1.2", "10.0.1.1"
SRC6, DST6, TGT6 = "fd00::1:2", "ff02::1:ff00:101", "fd00::1:1"


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("fixtures/golden")
    out.mkdir(parents=True, exist_ok=True)

    icmp = bytes(ICMP(type=8, id=0x1234, seq=9) / Raw(b"nettk-golden"))
    (out / "icmp_echo.hex").write_text(icmp.hex() + "\n")

    arp = bytes(Ether(dst="ff:ff:ff:ff:ff:ff", src=H1) /
                ARP(op=1, hwsrc=H1, psrc=IP1, pdst=GW))
    (out / "arp_request.hex").write_text(arp.hex() + "\n")

    # Attach to IPv6 so scapy computes the ICMPv6 checksum over the pseudo-header.
    ns = bytes(IPv6(src=SRC6, dst=DST6) /
               ICMPv6ND_NS(tgt=TGT6) /
               ICMPv6NDOptSrcLLAddr(lladdr=H1))[40:]
    (out / "icmp6_ns.hex").write_text(ns.hex() + "\n")

    echo6 = bytes(IPv6(src=SRC6, dst=TGT6) /
                  ICMPv6EchoRequest(id=0x1234, seq=9) / Raw(b"nettk-golden"))[40:]
    (out / "icmp6_echo.hex").write_text(echo6.hex() + "\n")

    for f in sorted(out.glob("*.hex")):
        print(f"wrote {f} ({len(f.read_text().strip()) // 2} bytes)")


if __name__ == "__main__":
    main()

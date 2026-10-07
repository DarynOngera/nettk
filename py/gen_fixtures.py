#!/usr/bin/env python3
"""Generate deterministic pcap fixtures for the decoder (Phase 1) and fuzz seeds.

usage: py/gen_fixtures.py [outdir]     (default: fixtures)

  basic.pcap      well-formed traffic: ARP, ICMP, TCP (options), UDP/DNS, 802.1Q, fragments
  malformed.pcap  hostile frames: truncation, bad IHL, bad TCP offset, oversize totlen,
                  looping DNS compression pointer. A decoder must reject these cleanly.
Timestamps are fixed so output is byte-for-byte reproducible.
"""
import struct
import sys
from pathlib import Path

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Dot1Q, Ether,
                       Raw, fragment, raw, wrpcap)

H1, H2, RT = "02:00:00:00:01:02", "02:00:00:00:02:02", "02:00:00:00:01:01"
IP1, IP2, GW = "10.0.1.2", "10.0.2.2", "10.0.1.1"


def stamp(pkts):
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000 + i * 0.001
    return pkts


def basic():
    pk = []
    pk.append(Ether(src=H1, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=H1, psrc=IP1, pdst=GW))
    pk.append(Ether(src=RT, dst=H1) / ARP(op=2, hwsrc=RT, psrc=GW, hwdst=H1, pdst=IP1))
    pk.append(Ether(src=H1, dst=RT) / IP(src=IP1, dst=IP2, ttl=64, id=1) /
              ICMP(type=8, id=0x1234, seq=1) / Raw(b"phase0-ping"))
    pk.append(Ether(src=RT, dst=H1) / IP(src=IP2, dst=IP1, ttl=63, id=2) /
              ICMP(type=0, id=0x1234, seq=1) / Raw(b"phase0-ping"))
    syn_opts = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (111, 0)),
                ("NOP", None), ("WScale", 7)]
    pk.append(Ether(src=H1, dst=RT) / IP(src=IP1, dst=IP2, id=3, flags="DF") /
              TCP(sport=40000, dport=80, flags="S", seq=1000, options=syn_opts))
    pk.append(Ether(src=RT, dst=H1) / IP(src=IP2, dst=IP1, id=4, flags="DF") /
              TCP(sport=80, dport=40000, flags="SA", seq=5000, ack=1001,
                  options=[("MSS", 1460), ("NOP", None), ("WScale", 7)]))
    pk.append(Ether(src=H1, dst=RT) / IP(src=IP1, dst=IP2, id=5) /
              TCP(sport=40000, dport=80, flags="PA", seq=1001, ack=5001) /
              Raw(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"))
    q = DNS(id=0xBEEF, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    pk.append(Ether(src=H1, dst=RT) / IP(src=IP1, dst="10.0.2.53", id=6) /
              UDP(sport=53000, dport=53) / q)
    r = DNS(id=0xBEEF, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"))
    pk.append(Ether(src=RT, dst=H1) / IP(src="10.0.2.53", dst=IP1, id=7) /
              UDP(sport=53, dport=53000) / r)
    pk.append(Ether(src=H1, dst=RT) / Dot1Q(vlan=50, prio=3) /
              IP(src=IP1, dst=IP2, id=8) / ICMP(id=1, seq=2))
    big = IP(src=IP1, dst=IP2, id=0x4242) / ICMP(id=9, seq=1) / Raw(b"A" * 3000)
    for f in fragment(big, fragsize=1480):
        pk.append(Ether(src=H1, dst=RT) / f)
    pk.append(Ether(src=H1, dst=RT) / IP(src=IP1, dst=IP2, id=9, ttl=1) /
              UDP(sport=33434, dport=33434) / Raw(b"traceroute-probe"))
    return stamp(pk)


def malformed():
    base = bytes(Ether(src=H1, dst=RT) / IP(src=IP1, dst=IP2) / TCP(sport=1, dport=2) / Raw(b"x" * 8))
    frames = []
    frames.append(base[:10])                        # shorter than an Ethernet header
    frames.append(base[:14 + 10])                   # IPv4 header cut mid-way
    f = bytearray(base); f[14] = 0x44               # IHL = 4 (16 bytes) < minimum 20
    frames.append(bytes(f))
    f = bytearray(base); f[14] = 0x4F               # IHL = 15 (60 bytes) beyond the frame
    frames.append(bytes(f))
    f = bytearray(base); f[16:18] = (0xFFFF).to_bytes(2, "big")   # total length > frame
    frames.append(bytes(f))
    f = bytearray(base); f[16:18] = (10).to_bytes(2, "big")       # total length < IHL
    frames.append(bytes(f))
    f = bytearray(base); f[14 + 20 + 12] = 0x10     # TCP data offset = 1 (4 bytes) < 5
    frames.append(bytes(f))
    f = bytearray(base); f[14 + 20 + 12] = 0xF0     # TCP data offset = 15 beyond the frame
    frames.append(bytes(f))
    # DNS name whose compression pointer points at itself (offset 12 -> 12): infinite loop bait
    dns = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c" + b"\x00\x01\x00\x01")
    frames.append(raw(Ether(src=H1, dst=RT) / IP(src=IP1, dst="10.0.2.53") /
                      UDP(sport=1234, dport=53) / Raw(dns)))
    return frames


def write_raw_pcap(path, frames):
    """Write raw byte strings as an Ethernet pcap (scapy cannot build runt frames)."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            fh.write(struct.pack("<IIII", 1_700_000_000, i * 1000, len(f), len(f)))
            fh.write(f)


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures")
    out.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out / "basic.pcap"), basic())
    write_raw_pcap(out / "malformed.pcap", malformed())
    print(f"wrote {out/'basic.pcap'} and {out/'malformed.pcap'}")


if __name__ == "__main__":
    main()

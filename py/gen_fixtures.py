#!/usr/bin/env python3
"""Generate deterministic pcap fixtures for the decoder (Phase 1) and fuzz seeds.

usage: py/gen_fixtures.py [outdir]     (default: fixtures)

  basic.pcap      well-formed IPv4: ARP, ICMP, TCP (options), UDP/DNS, 802.1Q, fragments
  ipv6.pcap       well-formed IPv6: ICMPv6 echo, NDP NS/NA, UDP
  malformed.pcap  hostile frames: truncation, bad IHL, bad TCP offset, oversize totlen,
                  looping DNS compression pointer. A decoder must reject these cleanly.
Timestamps are fixed so output is byte-for-byte reproducible.
"""
import struct
import sys
from pathlib import Path

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, ICMPv6EchoReply,
                       ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_NS,
                       ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, IP, IPv6,
                       TCP, UDP, Dot1Q, Ether, Raw, fragment, raw, wrpcap)

H1, H2, RT = "02:00:00:00:01:02", "02:00:00:00:02:02", "02:00:00:00:01:01"
IP1, IP2, GW = "10.0.1.2", "10.0.2.2", "10.0.1.1"
V6A, V6B = "fd00::1:2", "fd00::2:2"
LL1, LL2 = "fe80::200:ff:fe00:102", "fe80::200:ff:fe00:202"


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


def ipv6():
    pk = []
    pk.append(Ether(src=H1, dst=RT) / IPv6(src=V6A, dst=V6B, hlim=64) /
              ICMPv6EchoRequest(id=0x1234, seq=1) / Raw(b"v6-ping"))
    pk.append(Ether(src=RT, dst=H1) / IPv6(src=V6B, dst=V6A, hlim=63) /
              ICMPv6EchoReply(id=0x1234, seq=1) / Raw(b"v6-ping"))
    pk.append(Ether(src=H1, dst="33:33:ff:00:02:02") /
              IPv6(src=LL1, dst="ff02::1:ff00:202", hlim=255) /
              ICMPv6ND_NS(tgt=V6B) / ICMPv6NDOptSrcLLAddr(lladdr=H1))
    pk.append(Ether(src=RT, dst=H1) / IPv6(src=V6B, dst=LL1, hlim=255) /
              ICMPv6ND_NA(tgt=V6B, R=0, S=0, O=1) / ICMPv6NDOptDstLLAddr(lladdr=RT))
    pk.append(Ether(src=H1, dst=RT) / IPv6(src=V6A, dst=V6B, hlim=64) /
              UDP(sport=53000, dport=53) / Raw(b"\x00\x01" + b"q" * 6))
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


def arp_spoof():
    """One honest ARP exchange followed by attacks that each trip one monitor rule."""
    att = "02:00:00:00:00:03"
    wrong_src = "02:00:00:00:00:0a"
    ether_src = "02:00:00:00:00:0b"
    z = "00:00:00:00:00:00"
    pk = [
        Ether(src=H1, dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, hwsrc=H1, psrc="10.0.0.1", pdst="10.0.0.2"),
        Ether(src=H2, dst=H1) / ARP(op=2, hwsrc=H2, psrc="10.0.0.2", hwdst=H1, pdst="10.0.0.1"),
        # binding-change + duplicate-ip + unsolicited reply: attacker claims h2's IP
        Ether(src=att, dst=H1) / ARP(op=2, hwsrc=att, psrc="10.0.0.2", hwdst=H1, pdst="10.0.0.1"),
        # gratuitous announcement (sender IP == target IP)
        Ether(src=att, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=att, psrc="10.0.0.2", hwdst=z, pdst="10.0.0.2"),
        # flip-flop: back to the original MAC
        Ether(src=H2, dst=H1) / ARP(op=2, hwsrc=H2, psrc="10.0.0.2", hwdst=H1, pdst="10.0.0.1"),
        # Ethernet/ARP MAC mismatch on a fresh IP
        Ether(src=ether_src, dst=H1) /
        ARP(op=2, hwsrc=wrong_src, psrc="10.0.0.77", hwdst=H1, pdst="10.0.0.1"),
    ]
    return stamp(pk)


def arp_flood(n=20000):
    """Thousands of gratuitous bindings for distinct IPs: the table must stay bounded."""
    z = "00:00:00:00:00:00"
    pk = []
    for i in range(n):
        ip = f"10.7.{(i >> 8) & 0xff}.{i & 0xff}"
        mac = bytes([0x02, 0x00, 0x00, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff])
        pk.append(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                  ARP(op=2, hwsrc=mac, psrc=ip, hwdst=z, pdst=ip))
    return stamp(pk)


def dns_good():
    """Phase-5 DNS messages exercising the name codec: compression pointers,
    label+pointer, pointer-to-owner-start, escaped label bytes. Built as raw
    payloads so the wire bytes are exactly ours (scapy would re-serialize)."""
    hdr = lambda ident, flags, qd, an: bytes.fromhex(
        "%04x%04x%04x%04x00000000" % (ident, flags, qd, an))
    q_www = bytes.fromhex("03777777076578616d706c6503636f6d00") + b"\x00\x01\x00\x01"
    q_x01y = bytes.fromhex("03780179076578616d706c6503636f6d00") + b"\x00\x01\x00\x01"
    q_zffz = bytes.fromhex("037aff7a076578616d706c6503636f6d00") + b"\x00\x01\x00\x01"
    rr_a = bytes.fromhex("c00c000100010000012c0004") + bytes.fromhex("5db8d822")
    rr_alpha = bytes.fromhex("05616c706861c010000100010000012c0004") + bytes.fromhex("5db8d822")
    rr_alpha2 = bytes.fromhex("c021000500010000012c0005") + bytes.fromhex("0377777700")
    payloads = [
        hdr(0x1234, 0x0100, 1, 0) + q_www,      # plain query
        hdr(0x1234, 0x8180, 1, 1) + q_www + rr_a,   # answer owner = pointer to qname
        hdr(0x1235, 0x8180, 1, 2) + q_www + rr_alpha + rr_alpha2,  # label+ptr; ptr to owner start
        hdr(0x1236, 0x0100, 1, 0) + q_x01y,     # label contains 0x01
        hdr(0x1237, 0x0100, 1, 0) + q_zffz,     # label contains 0xff
    ]
    return [stamp([Ether(src=H1, dst=RT) / IP(src=IP1, dst="10.0.2.53", id=80 + i) /
                   UDP(sport=40000 + i, dport=53) / Raw(p)])[0]
            for i, p in enumerate(payloads)]


def dns_malformed():
    """Hostile DNS messages: the name codec must reject all of these cleanly."""
    hdr12 = bytes.fromhex("1234010000010000" + "0000" + "0000")
    frames = []
    def pkt(payload):
        frames.append(raw(Ether(src=H1, dst=RT) / IP(src=IP1, dst="10.0.2.53", id=90) /
                          UDP(sport=12345, dport=53) / Raw(payload)))
    # reserved label type bits 01 (0x41): neither a length nor a pointer
    pkt(hdr12 + b"\x41" + b"x" * 8)
    # compression pointer to itself (offset 12 -> 12): infinite loop bait
    pkt(hdr12 + b"\xc0\x0c" + b"\x00\x01\x00\x01")
    # forward pointer: target 14 is its own offset
    pkt(hdr12 + b"\x01a\xc0\x0e" + b"\x00\x01\x00\x01")
    # 130-pointer chain: every hop strictly decreases, but exceeds the hop cap
    ptrs = []
    for i in range(130):
        target = 0 if i == 0 else 3 + 2 * (i - 1)
        ptrs.append(bytes([0xc0 | (target >> 8), target & 0xff]))
    pkt(hdr12 + b"\x01a\x00" + b"".join(ptrs))
    # expanded name longer than 255 wire octets (5 x 52-byte labels)
    big = b"".join(bytes([52]) + bytes([0x61 + i]) * 52 for i in range(5)) + b"\x00"
    pkt(hdr12 + big)
    # label claims 7 octets but only 5 remain
    pkt(hdr12 + bytes.fromhex("03777777076578616d70"))
    # pointer octet cut off (needs 2 bytes, has 1) after a complete qname
    pkt(hdr12 + bytes.fromhex("0361626300") + b"\xc0")
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
    wrpcap(str(out / "ipv6.pcap"), ipv6())
    write_raw_pcap(out / "malformed.pcap", malformed())
    wrpcap(str(out / "arp-spoof.pcap"), arp_spoof())
    wrpcap(str(out / "arp-flood.pcap"), arp_flood())
    wrpcap(str(out / "dns-good.pcap"), dns_good())
    write_raw_pcap(out / "dns-malformed.pcap", dns_malformed())
    print("wrote dns-good.pcap, dns-malformed.pcap")
    print(f"wrote {out}/basic.pcap, ipv6.pcap, malformed.pcap, arp-spoof.pcap, arp-flood.pcap")


if __name__ == "__main__":
    main()

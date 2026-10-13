#!/usr/bin/env python3
"""Generate deterministic DHCP pcap fixtures (Phase 6).

usage: py/gen_dhcp_fixtures.py [outdir]     (default: fixtures)

  dhcp-good.pcap       well-formed DISCOVER/OFFER/REQUEST/ACK/NAK/DECLINE/RELEASE/INFORM
  dhcp-malformed.pcap  15 hostile messages the decoder must reject (status per frame)

Frames are built by hand so the DHCP payload bytes are exactly the RFC 2131
section 2 layout; scapy only wraps them in Ethernet/IPv4/UDP. Timestamps are
fixed so output is byte-for-byte reproducible.
"""
import socket
import struct
import sys
from pathlib import Path

from scapy.all import Ether, IP, Raw, UDP, wrpcap

MAGIC = b"\x63\x82\x53\x63"
MIN_SEND = 300

CLI_MAC = "02:00:00:00:06:0a"
SRV_MAC = "02:00:00:00:06:01"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"
SRV_IP = "10.0.6.1"
LEASED = "10.0.6.100"

M_DISCOVER, M_OFFER, M_REQUEST, M_DECLINE, M_ACK, M_NAK, M_RELEASE, M_INFORM = range(1, 9)

FLAG_BCAST = 0x8000


def _mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def _ip(a):
    return socket.inet_aton(a)


def bootp(op, xid, chaddr=CLI_MAC, ci="0.0.0.0", yi="0.0.0.0", si="0.0.0.0",
          gi="0.0.0.0", flags=0, htype=1, hlen=6, hops=0, secs=0):
    """240-byte BOOTP fixed header + magic cookie."""
    h = struct.pack(">BBBBIHH", op, htype, hlen, hops, xid, secs, flags)
    h += _ip(ci) + _ip(yi) + _ip(si) + _ip(gi)
    h += _mac(chaddr).ljust(16, b"\x00")
    h += b"\x00" * 64          # sname
    h += b"\x00" * 128         # file
    h += MAGIC
    assert len(h) == 240
    return h


def opt(code, data=b""):
    return bytes([code, len(data)]) + data


def o_msg(t):
    return opt(53, bytes([t]))


def o_u32(code, v):
    return opt(code, struct.pack(">I", v))


def o_ip(code, a):
    return opt(code, _ip(a))


def o_iplist(code, addrs):
    return opt(code, b"".join(_ip(a) for a in addrs))


END = b"\xff"


def pad(payload):
    """Clients and servers pad the BOOTP payload to the 300-byte minimum."""
    if len(payload) < MIN_SEND:
        payload += b"\x00" * (MIN_SEND - len(payload))
    return payload


def frame(eth_src, eth_dst, ip_src, ip_dst, sport, dport, payload, ident=70):
    return Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst, id=ident) / \
        UDP(sport=sport, dport=dport) / Raw(payload)


def dhcp_good():
    """The DORA exchange plus the other message types, all well formed."""
    xid = 0x3903f326
    pkts = []

    # 1. DISCOVER: no address yet, broadcast.
    p = bootp(1, xid, flags=FLAG_BCAST)
    p += o_msg(M_DISCOVER)
    p += opt(55, bytes([1, 3, 6, 15, 51, 54]))       # parameter request list
    p += opt(12, b"c1")                              # hostname
    p += opt(57, struct.pack(">H", 1500))            # max message size
    p += END
    pkts.append(frame(CLI_MAC, BCAST_MAC, "0.0.0.0", "255.255.255.255", 68, 67, pad(p), 70))

    # 2. OFFER: server -> client, broadcast because the client cannot be ARPed.
    p = bootp(2, xid, yi=LEASED, si=SRV_IP, flags=FLAG_BCAST)
    p += o_msg(M_OFFER)
    p += o_ip(54, SRV_IP)
    p += o_u32(51, 3600)
    p += o_ip(1, "255.255.255.0")
    p += o_iplist(3, [SRV_IP])
    p += o_iplist(6, [SRV_IP])
    p += o_u32(58, 1800)
    p += o_u32(59, 3150)
    p += END
    pkts.append(frame(SRV_MAC, BCAST_MAC, SRV_IP, "255.255.255.255", 67, 68, pad(p), 71))

    # 3. REQUEST: selects the server and asks for the offered address.
    p = bootp(1, xid, flags=FLAG_BCAST)
    p += o_msg(M_REQUEST)
    p += o_ip(50, LEASED)
    p += o_ip(54, SRV_IP)
    p += opt(12, b"c1")
    p += opt(55, bytes([1, 3, 6, 15, 51, 54]))
    p += END
    pkts.append(frame(CLI_MAC, BCAST_MAC, "0.0.0.0", "255.255.255.255", 68, 67, pad(p), 72))

    # 4. ACK: the lease is confirmed.
    p = bootp(2, xid, yi=LEASED, si=SRV_IP, flags=FLAG_BCAST)
    p += o_msg(M_ACK)
    p += o_ip(54, SRV_IP)
    p += o_u32(51, 3600)
    p += o_ip(1, "255.255.255.0")
    p += o_iplist(3, [SRV_IP])
    p += o_iplist(6, [SRV_IP])
    p += o_u32(58, 1800)
    p += o_u32(59, 3150)
    p += END
    pkts.append(frame(SRV_MAC, BCAST_MAC, SRV_IP, "255.255.255.255", 67, 68, pad(p), 73))

    # 5. NAK: wrong network, yiaddr is zero.
    p = bootp(2, xid, flags=FLAG_BCAST)
    p += o_msg(M_NAK)
    p += o_ip(54, SRV_IP)
    p += opt(56, b"wrong network")
    p += END
    pkts.append(frame(SRV_MAC, BCAST_MAC, SRV_IP, "255.255.255.255", 67, 68, pad(p), 74))

    # 6. DECLINE: client says the address is already in use.
    p = bootp(1, 0x3903f327, flags=FLAG_BCAST)
    p += o_msg(M_DECLINE)
    p += o_ip(50, LEASED)
    p += o_ip(54, SRV_IP)
    p += END
    pkts.append(frame(CLI_MAC, BCAST_MAC, "0.0.0.0", "255.255.255.255", 68, 67, pad(p), 75))

    # 7. RELEASE: unicast to the server after the lease is held.
    p = bootp(1, 0x3903f328, ci=LEASED)
    p += o_msg(M_RELEASE)
    p += o_ip(54, SRV_IP)
    p += END
    pkts.append(frame(CLI_MAC, SRV_MAC, LEASED, SRV_IP, 68, 67, pad(p), 76))

    # 8. INFORM: address is already configured, only parameters are wanted.
    p = bootp(1, 0x3903f329, ci=LEASED, flags=FLAG_BCAST)
    p += o_msg(M_INFORM)
    p += opt(55, bytes([1, 3, 6]))
    p += END
    pkts.append(frame(CLI_MAC, BCAST_MAC, LEASED, "255.255.255.255", 68, 67, pad(p), 77))

    # 9. OFFER with yiaddr 0 (hostile but well-formed; the client must not trust it).
    p = bootp(2, 0x3903f32a, si=SRV_IP, flags=FLAG_BCAST)
    p += o_msg(M_OFFER)
    p += o_ip(54, SRV_IP)
    p += END
    pkts.append(frame(SRV_MAC, BCAST_MAC, SRV_IP, "255.255.255.255", 67, 68, pad(p), 78))

    for i, p in enumerate(pkts):
        p.time = 1_700_100_000 + i * 0.001
    return pkts


def _malformed_payloads():
    """Each returns (payload, comment). The decoder must reject every one."""
    out = []
    xid = 0x11111111

    # 1. fewer than 240 bytes -> TRUNCATED
    out.append((bootp(1, xid)[:200], "short message"))

    # 2. wrong magic cookie -> MALFORMED
    bad = bytearray(bootp(1, xid))
    bad[236:240] = b"\xde\xad\xbe\xef"
    out.append((bytes(bad) + o_msg(M_DISCOVER) + END, "wrong cookie"))

    # 3. an option whose length runs past the end -> MALFORMED
    p = bootp(1, xid) + o_msg(M_DISCOVER) + bytes([54, 4])  # claims 4 octets, none follow
    out.append((p, "option length past end"))

    # 4. no END -> MALFORMED
    out.append((bootp(1, xid) + o_msg(M_DISCOVER), "no END"))

    # 5. option 53 with length 2 -> MALFORMED
    p = bootp(1, xid) + bytes([53, 2, M_DISCOVER, 0]) + END
    out.append((p, "option 53 length 2"))

    # 6. option 53 with an unknown value -> MALFORMED
    out.append((bootp(1, xid) + bytes([53, 1, 99]) + END, "option 53 bad value"))

    # 7. a repeated option -> MALFORMED
    out.append((bootp(1, xid) + o_msg(M_DISCOVER) + o_msg(M_DISCOVER) + END,
                "repeated option 53"))

    # 8. option 52 (overload) is out of scope -> UNSUPPORTED
    out.append((bootp(1, xid) + o_msg(M_DISCOVER) + opt(52, b"\x01") + END,
                "option 52 overload"))

    # 9. htype 1 with hlen 7 -> MALFORMED
    out.append((bootp(1, xid, hlen=7) + o_msg(M_DISCOVER) + END, "htype 1 hlen 7"))

    # 10. hlen above 16 -> MALFORMED
    out.append((bootp(1, xid, htype=0, hlen=17) + o_msg(M_DISCOVER) + END,
                "hlen 17"))

    # 11. server identifier with length 3 -> MALFORMED
    out.append((bootp(1, xid) + o_msg(M_DISCOVER) + opt(54, b"\x0a\x00\x06") + END,
                "server id length 3"))

    # 12. router list length 5 (not a multiple of 4) -> MALFORMED
    out.append((bootp(2, xid) + o_msg(M_OFFER) + opt(3, b"\x01\x02\x03\x04\x05") + END,
                "router length 5"))

    # 13. subnet mask length 3 -> MALFORMED
    out.append((bootp(2, xid) + o_msg(M_OFFER) + opt(1, b"\xff\xff\xff") + END,
                "mask length 3"))

    # 14. exactly 240 bytes, valid cookie, no options at all -> MALFORMED (no END)
    out.append((bootp(2, xid), "exactly 240 bytes, no END"))

    # 15. a bare option code with no length octet at the end -> MALFORMED
    out.append((bootp(1, xid) + o_msg(M_DISCOVER) + bytes([54]), "code with no length"))

    return out


def dhcp_malformed():
    pkts = []
    for i, (payload, _) in enumerate(_malformed_payloads()):
        pkts.append(frame(CLI_MAC, BCAST_MAC, "0.0.0.0", "255.255.255.255",
                          68, 67, payload, 100 + i))
    for i, p in enumerate(pkts):
        p.time = 1_700_200_000 + i * 0.001
    return pkts


def main():
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures")
    outdir.mkdir(parents=True, exist_ok=True)
    wrpcap(str(outdir / "dhcp-good.pcap"), dhcp_good())
    wrpcap(str(outdir / "dhcp-malformed.pcap"), dhcp_malformed())
    print(f"wrote {outdir}/dhcp-good.pcap ({len(dhcp_good())} frames)")
    print(f"wrote {outdir}/dhcp-malformed.pcap ({len(dhcp_malformed())} frames)")


if __name__ == "__main__":
    main()

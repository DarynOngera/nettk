#!/usr/bin/env python3
"""Lab authoritative DNS server for the nettk dnslab (stdlib only, no deps).

Serves RFC 1035 zone files (fully-qualified names, $TTL, '(' ')' spans, ';'
comments) over UDP and TCP (RFC 7766 2-octet framing) with:

  * answers with AA=1 (A AAAA NS CNAME SOA MX TXT; ANY = all types at a name)
  * referrals at delegation cuts: NS in authority, glue A in additional only
    when the NS target is in-bailiwick and has a record in the zone
    (RFC 1034 section 4.2.1; a glueless delegation gets no additional RRs)
  * wildcard synthesis with owner = qname (RFC 4592 section 2.2.1)
  * NODATA vs NXDOMAIN per RFC 2308 (SOA in authority, AA=1)
  * TC=1 when the response exceeds the client's advertised UDP size
    (RFC 2181 section 9; sizes below 512 count as 512, RFC 6891 section 6.2.3)
  * SCOPE: no recursion (RA=0 always), no caching, no DNSSEC, no AXFR.

--rewrite ADDR: replace additional-section glue A *values* with ADDR so the
delegation chain is walkable on loopback (where the glue IPs 10.0.5.x are not
running servers). Answer/authority data is never rewritten.

Lab-only tool: binds exactly --addr; used by lab/svc.sh as the nsd-less
fallback and (from M12 on) as the hostile responder for the dnsq spoof lab.
Every incoming byte is untrusted: all parsing is length-checked and bounded.
"""

import argparse
import socket
import struct
import sys
import threading

T_A, T_NS, T_CNAME, T_SOA, T_MX, T_TXT, T_AAAA, T_ANY = 1, 2, 5, 6, 15, 16, 28, 255
TYPES = (T_A, T_NS, T_CNAME, T_SOA, T_MX, T_TXT, T_AAAA)
QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}
TNAME = {v: k for k, v in QTYPE.items()}
N_EDNS = 4096
NO_EDNS = 512


# ---------- zone file parsing ----------

def strip_comment(line):
    in_q = False
    for i, c in enumerate(line):
        if c == '"':
            in_q = not in_q
        elif c == ";" and not in_q:
            return line[:i]
    return line


def tokenize(s):
    toks, i = [], 0
    while i < len(s):
        c = s[i]
        if c in " \t\n()":
            i += 1
            continue
        if c == '"':
            j = i + 1
            while j < len(s) and s[j] != '"':
                j += 1
            toks.append(s[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < len(s) and s[j] not in " \t\n()":
                j += 1
            toks.append(s[i:j])
            i = j
    return toks


def norm(name):
    """internal name form: lower-case, no trailing dot; root = ''"""
    if name == ".":
        return ""
    return name.rstrip(".").lower()


def contained(name, apex):
    return apex == "" or name == apex or name.endswith("." + apex)


def parse_zone(path):
    """-> (apex, records) where records: (normname, qtype) -> [rdata token lists]"""
    ttl = 300
    records = {}
    apex = None
    buf, paren = "", 0
    for raw in open(path).read().splitlines():
        line = strip_comment(raw).strip()
        if not line:
            continue
        buf += " " + line
        paren += line.count("(") - line.count(")")
        if paren > 0:
            continue
        toks = tokenize(buf)
        buf = ""
        if not toks:
            continue
        if toks[0] == "$TTL":
            ttl = int(toks[1])
            continue
        i = 1
        if i < len(toks) and toks[i].isdigit():  # explicit TTL
            ttl = int(toks[i])
            i += 1
        if i < len(toks) and toks[i] == "IN":
            i += 1
        if i >= len(toks):
            continue
        rtype = toks[i].upper()
        rdata = toks[i + 1:]
        rt = TNAME.get(rtype)
        if rt is None or not rdata:
            continue
        name = norm(toks[0])
        if rt == T_SOA and apex is None:
            apex = name
        records.setdefault((name, rt), []).append(rdata)
    if apex is None:
        sys.exit("error: no SOA record in %s" % path)
    return apex, records


# ---------- wire encoding ----------

def enc_name(name):
    if name == "":
        return b"\x00"
    out = bytearray()
    for lab in name.split("."):
        b = lab.encode("ascii")
        if not b or len(b) > 63:
            raise ValueError("bad label length in %r" % name)
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def enc_rdata(typ, toks):
    if typ == T_A:
        return socket.inet_aton(toks[0])
    if typ == T_AAAA:
        return socket.inet_pton(socket.AF_INET6, toks[0])
    if typ in (T_NS, T_CNAME):
        return enc_name(norm(toks[0]))
    if typ == T_MX:
        return struct.pack("!H", int(toks[0])) + enc_name(norm(toks[1]))
    if typ == T_SOA:
        out = enc_name(norm(toks[0])) + enc_name(norm(toks[1]))
        for v in toks[2:7]:
            out += struct.pack("!I", int(v))
        return out
    if typ == T_TXT:
        out = b""
        for s in toks:
            b = s.encode("latin-1")
            if len(b) > 255:
                raise ValueError("TXT character-string >255 bytes")
            out += bytes([len(b)]) + b
        return out
    raise ValueError("unsupported rdata type %d" % typ)


def rr(owner, typ, ttl, rd):
    return enc_name(owner) + struct.pack("!HHIH", typ, 1, ttl, len(rd)) + rd


def header(ident, rd, rcode, aa=0, tc=0, qd=1, an=0, ns=0, ar=0):
    fl = 0x8000 | (0x0100 if rd else 0) | (0x0400 if aa else 0) | (0x0200 if tc else 0) | (rcode & 0xF)
    return struct.pack("!HHHHHH", ident, fl, qd, an, ns, ar)


def assemble(ident, rd, rcode, qw, qh, aa, sections, want_opt):
    an, ns_, ar = sections
    if want_opt:
        ar = ar + [enc_name("") + struct.pack("!HHIH", 41, N_EDNS, 0, 0)]
    return (header(ident, rd, rcode, aa, 0, 1, len(an), len(ns_), len(ar)) + qw + qh
            + b"".join(an) + b"".join(ns_) + b"".join(ar))


# ---------- query parse (untrusted input; every read length-checked) ----------

def unpack_name(data, off, depth=0):
    labels = []
    while depth <= 100:
        if off >= len(data):
            return None, off
        l = data[off]
        if l == 0:
            return (".".join(labels) if labels else ""), off + 1
        if l & 0xC0 == 0xC0:  # compression pointer
            if off + 2 > len(data):
                return None, off
            ptr = ((l & 0x3F) << 8) | data[off + 1]
            rest, _ = unpack_name(data, ptr, depth + 1)
            if rest is None:
                return None, off
            return (".".join(labels + [rest]) if labels else rest), off + 2
        if l & 0xC0:
            return None, off
        if off + 1 + l > len(data):
            return None, off
        labels.append(data[off + 1:off + 1 + l].decode("ascii", "replace").lower())
        off += 1 + l
    return None, off


def parse_query(data):
    """-> (ident, flags, qname, qtype, qclass, edns_size) or None"""
    if len(data) < 12:
        return None
    ident, flags, qd, _an, _ns, ar = struct.unpack("!HHHHHH", data[:12])
    if qd != 1:
        return None
    off = 12
    name, off = unpack_name(data, off)
    if name is None or off + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    off += 4
    edns = None
    for _ in range(ar):
        _nm, off = unpack_name(data, off)
        if _nm is None or off + 10 > len(data):
            return None
        t, c, _ttl, rdl = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if t == 41:
            edns = c
        off += rdl
        if off > len(data):
            return None
    return ident, flags, name, qtype, qclass, edns


# ---------- response logic ----------

def longest_apex(zones, name):
    best = None
    for a in zones:
        if contained(name, a) and (best is None or len(a) > len(best)):
            best = a
    return best


def suffixes(name):
    parts = name.split(".") if name else []
    return [".".join(parts[i:]) for i in range(len(parts))] + [""]


def has_any(recs, name):
    return any(n == name for (n, _t) in recs)


OPT_GLUE_TYPES = (T_A, T_AAAA)


def glue_a(recs, apex, target, rewrite):
    out = []
    if not contained(target, apex):
        return out  # out-of-bailiwick: not our authoritative data (RFC 1034 4.2.1)
    for g in recs.get((target, T_A), []):
        val = socket.inet_aton(rewrite) if rewrite else enc_rdata(T_A, g)
        out.append(rr(target, T_A, 300, val))
    return out


def full(ident, rd, qw, qh, rcode, an, ns_, ar, aa, edns, limit=None):
    """assemble, then truncate to TC if over the client's advertised size.

    limit=None: advertise-size rule (UDP, RFC 6891 6.2.3). TCP callers pass
    limit=65535: no truncation over TCP (RFC 7766 section 7)."""
    if limit is None:
        limit = max(edns, NO_EDNS) if edns else NO_EDNS
    payload = assemble(ident, rd, rcode, qw, qh, aa, (an, ns_, ar), edns is not None)
    if len(payload) > limit:
        payload = assemble(ident, rd, rcode, qw, qh, aa, ([], [], []), False)
        fl = 0x8000 | (0x0100 if rd else 0) | (0x0400 if aa else 0) | 0x0200 | (rcode & 0xF)
        payload = struct.pack("!HHHHHH", ident, fl, 1, 0, 0, 0) + qw + qh
    return payload


def respond(zones, ident, flags, name, qtype, qclass, edns, rewrite, tcp=False):
    rd = flags & 0x0100
    lim = 65535 if tcp else None
    qw = enc_name(name)
    qh = struct.pack("!HH", qtype, qclass)
    if qclass != 1:
        return assemble(ident, rd, 5, qw, qh, 0, ([], [], []), False)
    apex = longest_apex(zones, name)
    if apex is None:
        return assemble(ident, rd, 5, qw, qh, 0, ([], [], []), False)
    recs = zones[apex]
    soa = rr(apex, T_SOA, 300, enc_rdata(T_SOA, recs[(apex, T_SOA)][0]))

    # referral: most specific delegation cut at-or-below the apex
    for cand in suffixes(name):
        if cand == apex or not contained(cand, apex):
            continue
        if (cand, T_NS) in recs:
            ns_ = [rr(cand, T_NS, 300, enc_rdata(T_NS, r)) for r in recs[(cand, T_NS)]]
            ar = []
            for r in recs[(cand, T_NS)]:
                ar += glue_a(recs, apex, norm(r[0]), rewrite)
            return full(ident, rd, qw, qh, 0, [], ns_, ar, 0, edns, lim)

    # direct answer / CNAME / ANY
    if qtype == T_ANY:
        sets = [(t, rd_) for t in TYPES for rd_ in recs.get((name, t), [])]
    elif (name, qtype) in recs:
        sets = [(qtype, rd_) for rd_ in recs[(name, qtype)]]
    elif (name, T_CNAME) in recs:
        sets = [(T_CNAME, rd_) for rd_ in recs[(name, T_CNAME)]]
    else:
        sets = []
    if sets:
        an = [rr(name, t, 300, enc_rdata(t, rd_)) for (t, rd_) in sets]
        ar = []
        for (t, rd_) in sets:
            if t == T_NS:
                ar += glue_a(recs, apex, norm(rd_[0]), rewrite)
        return full(ident, rd, qw, qh, 0, an, [], ar, 1, edns, lim)

    # negative: NODATA when the name exists, else NXDOMAIN (RFC 2308)
    if has_any(recs, name):
        return full(ident, rd, qw, qh, 0, [], [soa], [], 1, edns, lim)
    wk = ("*." + apex) if apex else "*"  # wildcard owner relative to the apex
    wild = [(t, rd_) for t in TYPES for rd_ in recs.get((wk, t), [])]
    if wild:
        want = [(t, rd_) for (t, rd_) in wild if qtype == T_ANY or t == qtype]
        if want:
            an = [rr(name, t, 300, enc_rdata(t, rd_)) for (t, rd_) in want]
            return full(ident, rd, qw, qh, 0, an, [], [], 1, edns, lim)
        return full(ident, rd, qw, qh, 0, [], [soa], [], 1, edns, lim)  # wildcard, wrong type
    return full(ident, rd, qw, qh, 3, [], [soa], [], 1, edns, lim)      # NXDOMAIN


def dispatch(data, zones, rewrite, tcp=False):
    p = parse_query(data)
    if p is None:
        ident = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0
        return header(ident, 0, 1)  # FORMERR
    ident, flags, name, qtype, qclass, edns = p
    return respond(zones, ident, flags, name, qtype, qclass, edns, rewrite, tcp)


# ---------- serving ----------

def handle_udp(sock, data, addr, zones, rewrite, verbose):
    try:
        sock.sendto(dispatch(data, zones, rewrite), addr)
    except OSError:
        pass
    if verbose:
        p = parse_query(data)
        print("%s:%d %s %s" % (addr[0], addr[1],
                               (p[2] + ".") if p and p[2] else (".",)[0] if p else "-",
                               QTYPE.get(p[3], p[3]) if p else "FORMERR"), flush=True)


def serve_udp(sock, zones, args):
    while True:
        data, addr = sock.recvfrom(65536)
        threading.Thread(target=handle_udp,
                         args=(sock, data, addr, zones, args.rewrite, args.verbose),
                         daemon=True).start()


def handle_tcp(conn, addr, zones, rewrite, verbose):
    with conn:
        buf = b""
        while True:
            while len(buf) < 2:  # RFC 7766 length prefix
                d = conn.recv(2 - len(buf))
                if not d:
                    return
                buf += d
            n = struct.unpack("!H", buf[:2])[0]
            body = buf[2:]
            while len(body) < n:
                d = conn.recv(n - len(body))
                if not d:
                    return
                body += d
            buf = body[n:]
            data = body[:n]
            resp = dispatch(data, zones, rewrite, tcp=True)
            conn.sendall(struct.pack("!H", len(resp)) + resp)
            if verbose:
                p = parse_query(data)
                print("tcp %s:%d %s %s" % (addr[0], addr[1],
                                           p[2] + ".", QTYPE.get(p[3], p[3])) if p else "tcp bad", flush=True)


def serve_tcp(sock, zones, args):
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_tcp,
                         args=(conn, addr, zones, args.rewrite, args.verbose),
                         daemon=True).start()


def main():
    ap = argparse.ArgumentParser(
        description="lab authoritative DNS server (nettk dnslab)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--addr", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=5305, help="bind port (default 5305)")
    ap.add_argument("--zone", action="append", required=True,
                    help="zone file to serve (repeatable); apex taken from its SOA")
    ap.add_argument("--rewrite", default=None,
                    help="rewrite additional-section glue A values to this address (loopback demos)")
    ap.add_argument("--verbose", action="store_true", help="log one line per query")
    args = ap.parse_args()

    zones = {}
    for zf in args.zone:
        apex, recs = parse_zone(zf)
        zones[apex] = recs
        print("dnsd: zone %r <- %s (%d record sets)" % (apex, zf, len(recs)))

    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    u.bind((args.addr, args.port))
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind((args.addr, args.port))
    t.listen(16)
    print("dnsd: listening %s:%d udp+tcp (rewrite=%s)" % (args.addr, args.port, args.rewrite))
    threading.Thread(target=serve_tcp, args=(t, zones, args), daemon=True).start()
    serve_udp(u, zones, args)


if __name__ == "__main__":
    main()
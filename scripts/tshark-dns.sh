#!/usr/bin/env bash
# Oracle: compare `sniff --dns` against tshark's DNS fields on a capture.
#
#   usage: scripts/tshark-dns.sh <file.pcap> [sniff-binary]
#
# What is compared per decoded message: id, flags, question name/type and
# ANCOUNT/NSCOUNT/ARCOUNT, plus the A, AAAA, CNAME, NS, MX, TXT and SOA mname
# values aggregated across all sections (tshark's dns.* fields span sections).
#
# Known, documented divergence: tshark's -T fields output is lossy for bytes it
# cannot print. Our names escape every non-printable octet as \DDD (RFC 1035
# section 5.1); tshark renders 0xff as U+FFFD and doubles the backslash on
# escapes. normalize_name() maps both to the same octet string, so the escaped
# label vectors are compared on equal footing.
#
# Frames the codec rejects are reported (status) and skipped; the expected
# statuses for fixtures/dns-malformed.pcap live in tests/unit/test_dns_name.c
# and tests/unit/test_dns_msg.c.
set -euo pipefail

[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 <file.pcap> [sniff-binary]" >&2; exit 2; }
pcap=$1
sniff=${2:-build/asan/bin/sniff}
[[ -x $sniff ]] || { echo "no sniffer at $sniff (run: make all)" >&2; exit 2; }
[[ -r $pcap ]] || { echo "cannot read $pcap" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$sniff" --dns -r "$pcap" >"$tmp/mine.txt" 2>/dev/null

tshark -r "$pcap" -T fields -E separator='|' -E occurrence=a \
    -e frame.number -e dns.id -e dns.flags -e dns.qry.name -e dns.qry.type \
    -e dns.count.answers -e dns.count.auth_rr -e dns.count.add_rr \
    -e dns.a -e dns.aaaa -e dns.cname -e dns.ns -e dns.mx.preference \
    -e dns.mx.mail_exchange -e dns.txt -e dns.soa.mname \
    >"$tmp/tshark.tsv" 2>/dev/null

python3 - "$tmp/mine.txt" "$tmp/tshark.tsv" "$pcap" <<'PY'
import re
import sys

mine_path, tshark_path, pcap = sys.argv[1], sys.argv[2], sys.argv[3]

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
         "MX": 15, "TXT": 16, "AAAA": 28, "OPT": 41}
NUM2TYPES = {v: k for k, v in TYPES.items()}


def decode_esc(s):
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            if (s[i + 1].isdigit() and i + 3 < len(s)
                    and s[i + 2].isdigit() and s[i + 3].isdigit()):
                out.append(int(s[i + 1:i + 4]) & 0xff)
                i += 4
            else:
                out.append(ord(s[i + 1]) & 0xff)
                i += 2
        else:
            out.append(ord(s[i]) & 0xff)
            i += 1
    return bytes(out)


def norm_name(s):
    s = s.rstrip(".").lower()
    s = s.replace("\ufffd", "\\255")
    s = s.replace("\\\\", "\\")
    return decode_esc(s)


def norm_txt(s):
    return decode_esc(s)


def split_csv(v):
    return [x for x in v.split(",") if x != ""]


errors = []
rejected = []
compared = 0

# --- our side ---------------------------------------------------------
mine = {}
cur = None
hdr_re = re.compile(
    r"^#(\d+) \S+ .*DNS id=0x([0-9a-f]+) flags=0x([0-9a-f]+)"
    r" qr=\d+ opcode=\d+ aa=\d+ tc=\d+ rd=\d+ ra=\d+ z=\d+ ad=\d+ cd=\d+"
    r" rcode=(\d+) qd=(\d+) an=(\d+) ns=(\d+) ar=(\d+)")
q_re = re.compile(r"^  q: (\S+) (\S+) (\d+)$")
rr_re = re.compile(r"^  (an|ns|ar)\[(\d+)\]: (\S+) (\S+) (\d+) (.*)$")
st_re = re.compile(r"^#(\d+) .*DNS status=(\S+)")

for line in open(mine_path):
    line = line.rstrip("\n")
    m = st_re.match(line)
    if m:
        rejected.append((int(m.group(1)), m.group(2)))
        cur = None
        continue
    m = hdr_re.match(line)
    if m:
        n = int(m.group(1))
        cur = {"id": int(m.group(2), 16), "flags": int(m.group(3), 16),
               "rcode": int(m.group(4)), "an": int(m.group(6)),
               "ns": int(m.group(7)), "ar": int(m.group(8)),
               "qname": None, "qtype": None, "lists": {}}
        mine[n] = cur
        continue
    if cur is None:
        continue
    m = q_re.match(line)
    if m:
        cur["qname"] = norm_name(m.group(1))
        cur["qtype"] = TYPES.get(m.group(2), -1)
        continue
    m = rr_re.match(line)
    if m:
        typ = m.group(4)
        rdata = m.group(6)
        lst = cur["lists"].setdefault(typ, [])
        if typ in ("A", "AAAA"):
            lst.append(rdata.strip())
        elif typ in ("CNAME", "NS"):
            lst.append(norm_name(rdata.strip()))
        elif typ == "TXT":
            lst.append(norm_txt(rdata))
        elif typ == "MX":
            pref, _, exch = rdata.partition(" ")
            cur["lists"].setdefault("MX_PREF", []).append(int(pref))
            lst.append(norm_name(exch.strip()))
        elif typ == "SOA":
            lst.append(norm_name(rdata.split(" ")[0]))
        continue

# --- tshark side ------------------------------------------------------
tfields = ["frame", "id", "flags", "qname", "qtype", "an", "ns", "ar",
           "a", "aaaa", "cname", "nsval", "mxpref", "mxexch", "txt", "soamname"]
theirs = {}
for line in open(tshark_path):
    line = line.rstrip("\n")
    if line == "":
        continue
    f = line.split("|")
    if len(f) < len(tfields):
        f += [""] * (len(tfields) - len(f))
    d = dict(zip(tfields, f))
    if d["frame"] == "" or d["id"] == "":
        continue
    n = int(d["frame"])
    t = {"id": int(d["id"], 16) if d["id"] else None,
         "flags": int(d["flags"], 16) if d["flags"] else None,
         "qname": norm_name(d["qname"]) if d["qname"] else None,
         "qtype": int(d["qtype"]) if d["qtype"] else None,
         "an": int(d["an"]) if d["an"] else 0,
         "ns": int(d["ns"]) if d["ns"] else 0,
         "ar": int(d["ar"]) if d["ar"] else 0,
         "lists": {}}
    if d["a"]:
        t["lists"]["A"] = split_csv(d["a"])
    if d["aaaa"]:
        t["lists"]["AAAA"] = split_csv(d["aaaa"])
    if d["cname"]:
        t["lists"]["CNAME"] = [norm_name(x) for x in split_csv(d["cname"])]
    if d["nsval"]:
        t["lists"]["NS"] = [norm_name(x) for x in split_csv(d["nsval"])]
    if d["mxpref"]:
        t["lists"]["MX_PREF"] = [int(x) for x in split_csv(d["mxpref"])]
    if d["mxexch"]:
        t["lists"]["MX"] = [norm_name(x) for x in split_csv(d["mxexch"])]
    if d["txt"]:
        t["lists"]["TXT"] = [norm_txt(x) for x in split_csv(d["txt"])]
    if d["soamname"]:
        t["lists"]["SOA"] = [norm_name(d["soamname"])]
    theirs[n] = t

# --- compare ----------------------------------------------------------
for n in sorted(mine):
    if n not in theirs:
        errors.append("frame %d: sniff decoded it, tshark did not" % n)
        continue
    a, b = mine[n], theirs[n]
    compared += 1
    if a["id"] != b["id"]:
        errors.append("frame %d: id 0x%04x != 0x%04x" % (n, a["id"], b["id"]))
    if a["flags"] != b["flags"]:
        errors.append("frame %d: flags 0x%04x != 0x%04x" % (n, a["flags"], b["flags"]))
    if a["qname"] != b["qname"]:
        errors.append("frame %d: qname %r != %r" % (n, a["qname"], b["qname"]))
    if a["qtype"] != b["qtype"]:
        errors.append("frame %d: qtype %r != %r" % (n, a["qtype"], b["qtype"]))
    for k in ("an", "ns", "ar"):
        if a[k] != b[k]:
            errors.append("frame %d: %sCOUNT %d != %d" % (n, k.upper(), a[k], b[k]))
    keys = set(a["lists"]) | set(b["lists"])
    for k in sorted(keys):
        if a["lists"].get(k, []) != b["lists"].get(k, []):
            errors.append("frame %d: %s %r != %r"
                          % (n, k, a["lists"].get(k, []), b["lists"].get(k, [])))

for n, st in rejected:
    print("frame %d: rejected (%s)" % (n, st))

if errors:
    print("FAIL %s: %d mismatch(es)" % (pcap, len(errors)))
    for e in errors:
        print("  " + e)
    sys.exit(1)

print("ok: %s: %d decoded message(s) match tshark (%d rejected frame(s))"
      % (pcap, compared, len(rejected)))
PY

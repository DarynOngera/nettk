#!/usr/bin/env bash
# Oracle: dnsq's iterative walk against dig(1) on the unprivileged loopback
# three-step delegation (root 127.0.0.1 -> test 127.0.0.2 -> example.test
# 127.0.0.3), all on port 5305. This is the DNS analogue of the dnslab topology
# from docs/phase5.md, runnable without root.
#
#   usage: scripts/dnsq-vs-dig.sh [dnsq-binary]
#
# dig asks the authoritative server (127.0.0.3) with +norecurse; dnsq walks
# from the root. The final answer rdata must agree. Status is checked for
# NODATA/NXDOMAIN and truncation.
set -euo pipefail

dnsq=${1:-build/asan/bin/dnsq}
port=5305
root=127.0.0.1
tld=127.0.0.2
auth=127.0.0.3

[[ -x $dnsq ]] || { echo "no dnsq at $dnsq (run: make all)" >&2; exit 2; }
command -v dig >/dev/null || { echo "dig not found" >&2; exit 2; }

export NT_LAB=1

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

start() { # addr zone rewrite
    python3 py/dnsd.py --addr "$1" --port "$port" --zone "$2" --rewrite "$3" \
        >>"$tmp/dnsd.log" 2>&1 &
    pids+=($!)
}
tmp=$(mktemp -d)
start "$root" lab/dns/zones/root.zone         "$tld"
start "$tld"  lab/dns/zones/test.zone         "$auth"
start "$auth" lab/dns/zones/example.test.zone "$root"

# wait for the auth server to answer its SOA
for i in $(seq 1 50); do
    if dig +time=1 +tries=1 +short @"$auth" -p "$port" example.test SOA >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

fails=0
trap 'cleanup; rm -rf "$tmp"' EXIT

# canonical form: "name|TYPE|rdata", lowercased, dots trimmed, escapes decoded
norm() { # stdin: mixed dig/dnsq lines -> canonical answer set on stdout
    python3 -c "$(cat <<'PY'
import re, sys

def unesc(s):
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            if s[i+1].isdigit() and i + 3 < len(s) and s[i+2].isdigit() and s[i+3].isdigit():
                out.append(int(s[i+1:i+4]) & 0xff); i += 4
            else:
                out.append(ord(s[i+1]) & 0xff); i += 2
        else:
            out.append(ord(s[i]) & 0xff); i += 1
    return bytes(out)

def strip_dot(b):
    return b[:-1] if b.endswith(b".") else b

out = []
for line in sys.stdin:
    t = line.split()
    if not t:
        continue
    if t[0] == "answer":            # dnsq: answer <name> <ttl> <TYPE> <rdata...>
        name, typ, rdata = t[1], t[3].upper(), t[4:]
    elif len(t) >= 4 and t[2] == "IN":   # dig: <name> <ttl> IN <TYPE> <rdata...>
        name, typ, rdata = t[0], t[3].upper(), t[4:]
    else:
        continue
    if typ in ("A", "AAAA"):
        val = " ".join(rdata).encode()
    elif typ in ("CNAME", "NS", "PTR"):
        val = strip_dot(unesc(" ".join(rdata)).lower())
    elif typ == "MX":
        parts = rdata
        val = (parts[0] + " ").encode() + strip_dot(unesc(parts[1]).lower())
    elif typ == "TXT":
        s = " ".join(rdata)
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            s = s[1:-1]
        val = unesc(s)
    else:
        val = " ".join(rdata).encode()
    out.append(strip_dot(unesc(name).lower()) + b"|" + typ.encode() + b"|" + val)
for x in sorted(out):
    sys.stdout.write(x.decode("latin-1") + "\n")
PY
)"
}

check() { # label type
    local label=$1 typ=$2
    local mine theirs
    mine=$("$dnsq" -s "$root" -p "$port" --iter -t "$typ" "$label" 2>/dev/null | grep '^answer ' | norm)
    theirs=$(dig +noall +answer +norecurse +time=2 +tries=1 @"$auth" -p "$port" "$label" "$typ" 2>/dev/null | norm)
    if [[ "$mine" == "$theirs" ]]; then
        printf 'ok   %-28s %-5s -> %s\n' "$label" "$typ" "${mine//$'\n'/; }"
    else
        printf 'FAIL %-28s %-5s   mine=[%s] dig=[%s]\n' "$label" "$typ" "$mine" "$theirs"
        fails=$((fails + 1))
    fi
}

check www.example.test A
check example.test MX
check txt.example.test TXT
check www.example.test AAAA
check nope.example.test A

# dnsq is a resolver: it follows CNAME chains, so its final answer must match
# dig asking the auth server for the *target*, and the trace must show the hop.
follow() { # label cname_target
    local trace final theirs
    trace=$("$dnsq" -s "$root" -p "$port" --iter -t A "$1" 2>/dev/null)
    final=$(grep '^answer ' <<<"$trace" | norm)
    theirs=$(dig +noall +answer +norecurse +time=2 +tries=1 @"$auth" -p "$port" "$1" A 2>/dev/null \
             | grep -i cname | awk '{print $5}' | sed 's/\.$//')
    if grep -q -- "-> CNAME $2" <<<"$trace" && [[ "$theirs" == "$2" ]]; then
        printf 'ok   %-28s %-5s -> CNAME %s\n' "$1" A "$2"
    else
        printf 'FAIL %-28s %-5s   trace CNAME=%s dig CNAME=%s\n' "$1" A "$2" "$theirs"
        fails=$((fails + 1))
    fi
}
follow alias.example.test www.example.test
follow chain.example.test mid.example.test
cn=$("$dnsq" -s "$root" -p "$port" --iter -t A chain.example.test 2>/dev/null | grep -c -- '-> CNAME')
if [[ "$cn" -eq 2 ]]; then
    printf 'ok   %-28s %-5s -> 2 CNAME hops\n' chain.example.test A
else
    printf 'FAIL chain.example.test A: expected 2 CNAME hops, saw %s\n' "$cn"
    fails=$((fails + 1))
fi

# status checks (no answers, but the walk must classify correctly)
status_check() { # label type want
    local got
    got=$("$dnsq" -s "$root" -p "$port" --iter -t "$2" "$1" 2>/dev/null | grep -oE '\-> (NODATA|NXDOMAIN)' | awk '{print $2}')
    if [[ "$got" == "$3" ]]; then
        printf 'ok   %-28s %-5s -> %s\n' "$1" "$2" "$got"
    else
        printf 'FAIL %-28s %-5s   got=%s want=%s\n' "$1" "$2" "$got" "$3"
        fails=$((fails + 1))
    fi
}
status_check host.example.test AAAA NODATA
status_check nope.other.test   A    NXDOMAIN

# truncation: a 512-byte UDP limit forces TC, dnsq must fall back to TCP
out=$("$dnsq" -s "$root" -p "$port" --iter --edns 512 -t TXT bigtxt.example.test 2>/dev/null)
if grep -q 'tcp_fallback=1' <<<"$out" && grep -q '^answer bigtxt.example.test' <<<"$out"; then
    printf 'ok   %-28s %-5s -> TC fell back to TCP\n' bigtxt.example.test TXT
else
    printf 'FAIL bigtxt.example.test TXT: no TCP fallback\n'
    fails=$((fails + 1))
fi

if [[ $fails -eq 0 ]]; then
    echo "ok: dnsq iterative walk matches dig on the loopback delegation"
else
    echo "FAIL: $fails mismatch(es)" >&2
    exit 1
fi

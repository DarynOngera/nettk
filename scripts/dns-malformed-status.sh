#!/usr/bin/env bash
# Gate: every hostile DNS frame in fixtures/dns-malformed.pcap must be rejected
# by `sniff --dns` with the expected nt_status, and no frame may crash.
#
#   usage: scripts/dns-malformed-status.sh [sniff-binary]
set -euo pipefail

sniff=${1:-build/asan/bin/sniff}
pcap=fixtures/dns-malformed.pcap
[[ -x $sniff ]] || { echo "no sniffer at $sniff (run: make all)" >&2; exit 2; }
[[ -r $pcap ]] || { echo "cannot read $pcap (run: make fixtures)" >&2; exit 2; }

# One line per frame, in fixture order. See py/gen_fixtures.py dns_malformed().
expected=(
    NT_ERR_MALFORMED    # reserved label type bits 01
    NT_ERR_MALFORMED    # compression pointer to itself
    NT_ERR_MALFORMED    # forward compression pointer
    NT_ERR_MALFORMED    # 200-hop pointer chain over the hop cap
    NT_ERR_MALFORMED    # expanded name longer than 255 wire octets
    NT_ERR_TRUNCATED    # label claims 7 octets but only 5 remain
    NT_ERR_TRUNCATED    # pointer octet cut off
    NT_ERR_UNSUPPORTED  # more than one question
    NT_ERR_MALFORMED    # A with RDLENGTH 3
    NT_ERR_MALFORMED    # TXT char-string overruns RDATA
    NT_ERR_MALFORMED    # a second OPT record
    NT_ERR_MALFORMED    # OPT with a non-root owner
    NT_ERR_TRUNCATED    # RDLENGTH beyond the message
    NT_ERR_TRUNCATED    # ANCOUNT 20 with no records
    NT_ERR_TRUNCATED    # 11-byte header
)

mapfile -t got < <("$sniff" --dns -r "$pcap" 2>/dev/null | grep -oE 'DNS status=[A-Z_]+' | sed 's/DNS status=//')

fail=0
if [[ ${#got[@]} -ne ${#expected[@]} ]]; then
    echo "FAIL: sniff printed ${#got[@]} status lines, expected ${#expected[@]}" >&2
    fail=1
fi
for i in "${!expected[@]}"; do
    g=${got[$i]:-<missing>}
    if [[ "$g" != "${expected[$i]}" ]]; then
        echo "FAIL: frame $((i + 1)): got $g want ${expected[$i]}" >&2
        fail=1
    fi
done
[[ $fail -eq 0 ]] || exit 1
echo "ok: $pcap: ${#expected[@]} hostile frames rejected with the expected status"

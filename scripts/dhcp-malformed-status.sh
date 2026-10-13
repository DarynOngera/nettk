#!/usr/bin/env bash
# Gate: every hostile DHCP frame in fixtures/dhcp-malformed.pcap must be rejected
# by `sniff --dhcp` with the expected nt_status, and no frame may crash.
#
#   usage: scripts/dhcp-malformed-status.sh [sniff-binary]
set -euo pipefail

sniff=${1:-build/asan/bin/sniff}
pcap=fixtures/dhcp-malformed.pcap
[[ -x $sniff ]] || { echo "no sniffer at $sniff (run: make all)" >&2; exit 2; }
[[ -r $pcap ]] || { echo "cannot read $pcap (run: make fixtures)" >&2; exit 2; }

# One line per frame, in fixture order. See py/gen_dhcp_fixtures.py.
expected=(
    NT_ERR_TRUNCATED    # 200-byte message (< 240)
    NT_ERR_MALFORMED    # wrong magic cookie
    NT_ERR_MALFORMED    # option length past the end
    NT_ERR_MALFORMED    # no END
    NT_ERR_MALFORMED    # option 53 length 2
    NT_ERR_MALFORMED    # option 53 value 99
    NT_ERR_MALFORMED    # repeated option 53
    NT_ERR_UNSUPPORTED  # option 52 (overload)
    NT_ERR_MALFORMED    # htype 1 with hlen 7
    NT_ERR_MALFORMED    # hlen 17
    NT_ERR_MALFORMED    # server id length 3
    NT_ERR_MALFORMED    # router length 5
    NT_ERR_MALFORMED    # mask length 3
    NT_ERR_MALFORMED    # exactly 240 bytes, no END
    NT_ERR_MALFORMED    # option code with no length octet
)

mapfile -t got < <("$sniff" --dhcp -r "$pcap" 2>/dev/null | grep -oE 'DHCP status=[A-Z_]+' | sed 's/DHCP status=//')

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

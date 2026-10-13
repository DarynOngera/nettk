#!/usr/bin/env bash
# Oracle: compare `sniff --dhcp` against tshark's BOOTP/DHCP fields.
#
#   usage: scripts/tshark-dhcp.sh <file.pcap> [sniff-binary]
#
# Per frame we compare: op, htype, hlen, xid, secs, flags, ciaddr/yiaddr/siaddr/
# giaddr, chaddr, DHCP message type, and the option values we decode (server id,
# requested ip, lease, T1, T2, mask, router, dns, hostname, message). Frames the
# decoder rejects are reported and skipped; fixtures/dhcp-malformed.pcap is gated
# separately by scripts/dhcp-malformed-status.sh.
set -euo pipefail

[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 <file.pcap> [sniff-binary]" >&2; exit 2; }
pcap=$1
sniff=${2:-build/asan/bin/sniff}
[[ -x $sniff ]] || { echo "no sniffer at $sniff (run: make all)" >&2; exit 2; }
[[ -r $pcap ]] || { echo "cannot read $pcap (run: make fixtures)" >&2; exit 2; }
command -v tshark >/dev/null 2>&1 || { echo "tshark not installed" >&2; exit 2; }

ours=$(mktemp)
theirs=$(mktemp)
trap 'rm -f "$ours" "$theirs"' EXIT

# --- our side: fold the multi-line records into a fixed-column TSV ----------
"$sniff" --dhcp -r "$pcap" 2>/dev/null | awk '
function emit() {
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
        f["op"], f["htype"], f["hlen"], f["xid"], f["secs"], f["flags"],
        f["ci"], f["yi"], f["si"], f["gi"], f["chaddr"], f["type"],
        f["server_id"], f["requested"], f["lease"], f["t1"], f["t2"],
        f["mask"], f["router"], f["dns"], f["hostname"], f["msg"]
}
/^#/ {
    if (started) emit()
    started = 1
    delete f
    n = split($0, a, " ")
    for (i = 1; i <= n; i++) {
        p = index(a[i], "=")
        if (p > 1) f[substr(a[i], 1, p - 1)] = substr(a[i], p + 1)
    }
    next
}
/^  / {
    s = substr($0, 3)
    p = index(s, "=")
    if (p > 1) f[substr(s, 1, p - 1)] = substr(s, p + 1)
    next
}
END { if (started) emit() }
' >"$ours"

# --- tshark side: same columns, numeric op/type mapped to our labels ---------
tshark -r "$pcap" -T fields -E separator=/t -E occurrence=f \
    -e dhcp.type -e dhcp.hw.type -e dhcp.hw.len -e dhcp.id -e dhcp.secs -e dhcp.flags \
    -e dhcp.ip.client -e dhcp.ip.your -e dhcp.ip.server -e dhcp.ip.relay -e dhcp.hw.mac_addr \
    -e dhcp.option.dhcp -e dhcp.option.dhcp_server_id -e dhcp.option.requested_ip_address \
    -e dhcp.option.ip_address_lease_time -e dhcp.option.renewal_time_value \
    -e dhcp.option.rebinding_time_value -e dhcp.option.subnet_mask -e dhcp.option.router \
    -e dhcp.option.domain_name_server -e dhcp.option.hostname -e dhcp.option.message \
    2>/dev/null | awk -F'\t' '
BEGIN {
    m[1]="DISCOVER"; m[2]="OFFER"; m[3]="REQUEST"; m[4]="DECLINE"
    m[5]="ACK"; m[6]="NAK"; m[7]="RELEASE"; m[8]="INFORM"
}
{
    op = ($1 == "1" ? "REQUEST" : ($1 == "2" ? "REPLY" : $1))
    typ = ($12 == "" ? "-" : ($12 in m ? m[$12] : $12))
    ht = $2; sub(/^0x0*/, "", ht); if (ht == "") ht = "0"
    print op"\t"ht"\t"$3"\t"$4"\t"$5"\t"$6"\t"$7"\t"$8"\t"$9"\t"$10"\t"$11"\t"typ"\t"$13"\t"$14"\t"$15"\t"$16"\t"$17"\t"$18"\t"$19"\t"$20"\t"$21"\t"$22
}
' >"$theirs"

if ! diff -u "$theirs" "$ours" >/tmp/nettk_dhcp_diff.$$ 2>&1; then
    echo "FAIL: $pcap: sniff --dhcp diverges from tshark" >&2
    cat /tmp/nettk_dhcp_diff.$$ >&2
    rm -f /tmp/nettk_dhcp_diff.$$
    exit 1
fi
rm -f /tmp/nettk_dhcp_diff.$$

n=$(wc -l <"$ours")
echo "ok: $pcap: $n DHCP message(s) match tshark"

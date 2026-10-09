/* libFuzzer harness for the M1-M3 matching/quote code.
 *
 * Build:  make fuzz
 * Run:    build/fuzz/fuzz_match fuzz/corpus -max_total_time=300
 *
 * It decodes a frame, then drives the echo-reply matchers and the ICMP error
 * quote parser on whatever bytes the frame happened to contain. All input is
 * untrusted; the matchers must return NT_INVALID rather than read past bounds. */
#include "nettk.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nt_packet pkt;
    (void)nt_decode_frame(data, size, &pkt);

    if (pkt.has_icmp) {
        nt_quote q;
        (void)nt_icmp_quote_parse(&pkt.icmp, &q);

        nt_echo_probe probe;
        memset(&probe, 0, sizeof probe);
        probe.id = (uint16_t)((pkt.icmp.rest.data != NULL && pkt.icmp.rest.len >= 2)
                                  ? ((uint16_t)pkt.icmp.rest.data[0] << 8 | pkt.icmp.rest.data[1])
                                  : 0);
        probe.src = pkt.has_ipv4 ? pkt.ip4.src : 0;
        probe.data = pkt.icmp.rest.data;
        probe.datalen = pkt.icmp.rest.len;
        (void)nt_match_icmp_echo_reply(&pkt.icmp, probe.src, &probe);
    }

    if (pkt.has_icmpv6) {
        nt_echo_probe probe;
        memset(&probe, 0, sizeof probe);
        probe.id = (uint16_t)((pkt.icmpv6.rest.data != NULL && pkt.icmpv6.rest.len >= 2)
                                  ? ((uint16_t)pkt.icmpv6.rest.data[0] << 8 | pkt.icmpv6.rest.data[1])
                                  : 0);
        (void)nt_match_icmp6_echo_reply(&pkt.icmpv6, pkt.ip6.src, &probe);
    }
    return 0;
}

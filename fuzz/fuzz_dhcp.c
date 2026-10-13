/* libFuzzer harness for the DHCP codec (M19, phase 6).
 *
 * Build:  make fuzz          (needs clang)
 * Seeds:  scripts/fuzz-seeds-dhcp.sh fuzz/corpus-dhcp
 * Run:    build/fuzz/fuzz_dhcp fuzz/corpus-dhcp -max_total_time=300
 *
 * Feeds arbitrary bytes to nt_dhcp_decode, then rebuilds the message from the
 * decoded fields and re-decodes it, so the builder is fuzzed with values the
 * decoder accepted. */
#include "dhcp.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nt_dhcp m;

    if (nt_dhcp_decode(data, size, &m) != NT_OK)
        return 0;

    /* Walk whatever the decoder recorded; the matchers must never crash. */
    const uint8_t ch[6] = { 0x02, 0x00, 0x00, 0x00, 0x06, 0x0a };
    (void)nt_dhcp_match_offer(&m, m.xid, ch);
    (void)nt_dhcp_match_ack(&m, m.xid, ch, m.yiaddr);
    (void)nt_dhcp_match_nak(&m, m.xid, ch);

    /* Round-trip through the builder. */
    nt_dhcp_out o;
    memset(&o, 0, sizeof o);
    o.op = m.op;
    o.htype = m.htype;
    o.hlen = m.hlen;
    o.hops = m.hops;
    o.xid = m.xid;
    o.secs = m.secs;
    o.flags = m.flags;
    o.ciaddr = m.ciaddr;
    o.yiaddr = m.yiaddr;
    o.siaddr = m.siaddr;
    o.giaddr = m.giaddr;
    memcpy(o.chaddr, m.chaddr, sizeof o.chaddr);

    uint8_t out[1024];
    size_t outlen = 0;
    if (nt_dhcp_build(&o, out, sizeof out, &outlen) == NT_OK) {
        nt_dhcp m2;
        (void)nt_dhcp_decode(out, outlen, &m2);
    }
    return 0;
}

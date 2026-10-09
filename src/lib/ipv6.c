#include "nettk.h"

#include <string.h>

#define NT_IPV6_HDR 40

nt_status nt_ipv6_decode(const uint8_t *buf, size_t len, nt_ipv6 *out)
{
    memset(out, 0, sizeof *out);
    if (!need(len, 0, NT_IPV6_HDR)) {
        return NT_ERR_TRUNCATED;
    }
    if ((rd8(buf, 0) >> 4) != 6) {
        return NT_ERR_MALFORMED;
    }

    out->payload_len = rd16be(buf, 4);
    out->next_hdr = rd8(buf, 6);
    out->hop_limit = rd8(buf, 7);
    memcpy(out->src, buf + 8, 16);
    memcpy(out->dst, buf + 24, 16);

    if ((size_t)out->payload_len > len - NT_IPV6_HDR) {
        return NT_ERR_TRUNCATED; /* no jumbograms this phase */
    }

    out->payload.data = buf + NT_IPV6_HDR;
    out->payload.len = out->payload_len;
    out->is_fragment = 0;
    return NT_OK;
}

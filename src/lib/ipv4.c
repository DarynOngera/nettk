#include "nettk.h"

#include <string.h>

#define NT_IPV4_MIN 20

nt_status nt_ipv4_decode(const uint8_t *buf, size_t len, nt_ipv4 *out)
{
    memset(out, 0, sizeof *out);
    if (!need(len, 0, NT_IPV4_MIN)) {
        return NT_ERR_TRUNCATED;
    }

    uint8_t ver_ihl = rd8(buf, 0);
    if ((ver_ihl >> 4) != 4) {
        return NT_ERR_MALFORMED;
    }
    out->ihl = (uint8_t)(ver_ihl & 0x0fu);
    if (out->ihl < 5) {
        return NT_ERR_MALFORMED;
    }

    size_t hsize = (size_t)out->ihl * 4;
    if (hsize > len) {
        return NT_ERR_TRUNCATED;
    }

    out->tos = rd8(buf, 1);
    out->totlen = rd16be(buf, 2);
    if (out->totlen < hsize) {
        return NT_ERR_MALFORMED;
    }
    if ((size_t)out->totlen > len) {
        return NT_ERR_TRUNCATED;
    }

    out->id = rd16be(buf, 4);
    uint16_t ff = rd16be(buf, 6);
    out->flag_df = (uint8_t)((ff >> 14) & 1u);
    out->flag_mf = (uint8_t)((ff >> 13) & 1u);
    out->frag_off = (uint16_t)(ff & 0x1fffu);
    out->ttl = rd8(buf, 8);
    out->proto = rd8(buf, 9);
    out->src = rd32be(buf, 12);
    out->dst = rd32be(buf, 16);

    out->options.data = buf + NT_IPV4_MIN;
    out->options.len = hsize - NT_IPV4_MIN;
    out->payload.data = buf + hsize;
    out->payload.len = (size_t)out->totlen - hsize;

    out->is_fragment = out->flag_mf || out->frag_off != 0;
    out->has_l4 = out->frag_off == 0;
    out->hdr_csum = nt_csum_final(nt_csum_partial(buf, hsize)) == 0
                        ? NT_CSUM_VALID
                        : NT_CSUM_INVALID;
    return NT_OK;
}

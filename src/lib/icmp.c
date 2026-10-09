#include "nettk.h"

#include <string.h>

#define NT_ICMP_MIN 8

nt_status nt_icmp_decode(const uint8_t *buf, size_t len, nt_icmp *out)
{
    memset(out, 0, sizeof *out);
    if (!need(len, 0, NT_ICMP_MIN)) {
        return NT_ERR_TRUNCATED;
    }

    out->type = rd8(buf, 0);
    out->code = rd8(buf, 1);
    out->csum = rd16be(buf, 2);
    out->rest.data = buf + 4;
    out->rest.len = len - 4;
    out->csum_state = nt_csum_final(nt_csum_partial(buf, len)) == 0
                          ? NT_CSUM_VALID
                          : NT_CSUM_INVALID;
    return NT_OK;
}

nt_status nt_icmp6_decode(const uint8_t *buf, size_t len, const nt_pseudo *ph, nt_icmp *out)
{
    memset(out, 0, sizeof *out);
    if (!need(len, 0, NT_ICMP_MIN)) {
        return NT_ERR_TRUNCATED;
    }

    out->type = rd8(buf, 0);
    out->code = rd8(buf, 1);
    out->csum = rd16be(buf, 2);
    out->rest.data = buf + 4;
    out->rest.len = len - 4;

    /* NDP neighbour solicitation/advertisement (RFC 4861 s4.3/4.4): 4 reserved
     * bytes then the 16-byte target address. Options after it are out of scope. */
    if (out->type == 135 || out->type == 136) {
        if (out->rest.len < 20) {
            return NT_ERR_TRUNCATED;
        }
        memcpy(out->target, buf + 8, 16);
        out->has_target = 1;
    }

    if (ph == NULL) {
        out->csum_state = NT_CSUM_NOT_CHECKED;
    } else {
        uint32_t sum = nt_csum_pseudo6(ph->src6, ph->dst6, NT_IPPROTO_ICMPV6, (uint32_t)len);
        sum = nt_csum_add(sum, buf, len);
        out->csum_state = nt_csum_final(sum) == 0 ? NT_CSUM_VALID : NT_CSUM_INVALID;
    }
    return NT_OK;
}

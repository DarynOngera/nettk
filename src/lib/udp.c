#include "nettk.h"

#include <string.h>

#define NT_UDP_MIN 8

nt_status nt_udp_decode(const uint8_t *buf, size_t len, const nt_pseudo *ph, nt_udp *out)
{
    memset(out, 0, sizeof *out);
    if (!need(len, 0, NT_UDP_MIN)) {
        return NT_ERR_TRUNCATED;
    }

    out->sport = rd16be(buf, 0);
    out->dport = rd16be(buf, 2);
    out->len = rd16be(buf, 4);
    out->csum = rd16be(buf, 6);

    if (out->len < NT_UDP_MIN) {
        return NT_ERR_MALFORMED;
    }
    if ((size_t)out->len > len) {
        return NT_ERR_TRUNCATED;
    }

    out->payload.data = buf + NT_UDP_MIN;
    out->payload.len = (size_t)out->len - NT_UDP_MIN;

    if (ph == NULL || (out->csum == 0 && ph->family == 4)) {
        out->csum_state = NT_CSUM_NOT_CHECKED; /* IPv4 UDP checksum 0 means absent */
    } else {
        uint32_t sum = ph->family == 4
                           ? nt_csum_pseudo4(ph->src4, ph->dst4, NT_IPPROTO_UDP, out->len)
                           : nt_csum_pseudo6(ph->src6, ph->dst6, NT_IPPROTO_UDP, out->len);
        sum = nt_csum_add(sum, buf, out->len);
        out->csum_state = nt_csum_final(sum) == 0 ? NT_CSUM_VALID : NT_CSUM_INVALID;
    }
    return NT_OK;
}

#include "nettk.h"

#include <string.h>

#define NT_TCP_MIN 20
#define NT_TCP_OPT_CAP 64

static nt_status parse_options(nt_tcp *out)
{
    const uint8_t *op = out->options.data;
    size_t olen = out->options.len;
    size_t i = 0;
    unsigned steps = 0;

    while (i < olen && steps++ < NT_TCP_OPT_CAP) {
        uint8_t kind = op[i];
        if (kind == 0) { /* End of option list */
            break;
        }
        if (kind == 1) { /* NOP */
            i++;
            continue;
        }
        if (i + 1 >= olen) {
            return NT_ERR_MALFORMED;
        }
        uint8_t olenv = op[i + 1];
        if (olenv < 2) {
            return NT_ERR_MALFORMED;
        }
        if (i + olenv > olen) {
            return NT_ERR_TRUNCATED;
        }
        switch (kind) {
        case 2: if (olenv == 4)  out->mss = (int)rd16be(op, i + 2); break;
        case 3: if (olenv == 3)  out->wscale = op[i + 2]; break;
        case 4: if (olenv == 2)  out->sack_ok = 1; break;
        case 8: if (olenv == 10) {
                    out->has_ts = 1;
                    out->ts_val = rd32be(op, i + 2);
                    out->ts_ecr = rd32be(op, i + 6);
                }
                break;
        default: break; /* ignored by length */
        }
        i += olenv;
    }
    return NT_OK;
}

nt_status nt_tcp_decode(const uint8_t *buf, size_t len, const nt_pseudo *ph, nt_tcp *out)
{
    memset(out, 0, sizeof *out);
    out->mss = -1;
    out->wscale = -1;

    if (!need(len, 0, NT_TCP_MIN)) {
        return NT_ERR_TRUNCATED;
    }

    out->sport = rd16be(buf, 0);
    out->dport = rd16be(buf, 2);
    out->seq = rd32be(buf, 4);
    out->ack = rd32be(buf, 8);

    uint8_t off_byte = rd8(buf, 12);
    out->data_off = (uint8_t)(off_byte >> 4);
    out->flags = (uint16_t)(((off_byte & 0x01u) << 8) | rd8(buf, 13));

    out->window = rd16be(buf, 14);
    out->csum = rd16be(buf, 16);
    out->urg = rd16be(buf, 18);

    if (out->data_off < 5) {
        return NT_ERR_MALFORMED;
    }
    size_t hsize = (size_t)out->data_off * 4;
    if (hsize > len) {
        return NT_ERR_TRUNCATED;
    }

    out->options.data = buf + NT_TCP_MIN;
    out->options.len = hsize - NT_TCP_MIN;
    out->payload.data = buf + hsize;
    out->payload.len = len - hsize;

    nt_status os = parse_options(out);
    if (os != NT_OK) {
        return os;
    }

    if (ph == NULL) {
        out->csum_state = NT_CSUM_NOT_CHECKED;
    } else {
        uint32_t sum = ph->family == 4
                           ? nt_csum_pseudo4(ph->src4, ph->dst4, NT_IPPROTO_TCP, (uint16_t)len)
                           : nt_csum_pseudo6(ph->src6, ph->dst6, NT_IPPROTO_TCP, (uint32_t)len);
        sum = nt_csum_add(sum, buf, len);
        out->csum_state = nt_csum_final(sum) == 0 ? NT_CSUM_VALID : NT_CSUM_INVALID;
    }
    return NT_OK;
}

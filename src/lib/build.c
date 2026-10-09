/*
 * Packet builders (M1). Pure: no I/O, no allocation, no globals.
 *
 * Every builder validates cap before each write and computes its own checksums
 * with the Phase 1 nt_csum_* helpers. Checksum fields are written in network
 * byte order; all other multi-byte fields too.
 */
#include "nettk.h"

#include <string.h>

static void put16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

nt_status nt_build_icmp_echo(uint8_t *out, size_t cap, size_t *outlen,
                             uint8_t type, uint16_t id, uint16_t seq,
                             const uint8_t *data, size_t datalen)
{
    if (out == NULL || outlen == NULL)
        return NT_ERR_MALFORMED;
    if (datalen > 0 && data == NULL)
        return NT_ERR_MALFORMED;

    size_t len = 8 + datalen;
    if (cap < len)
        return NT_ERR_TRUNCATED;

    out[0] = type;
    out[1] = 0;
    put16be(out + 2, 0); /* checksum placeholder */
    put16be(out + 4, id);
    put16be(out + 6, seq);
    if (datalen > 0)
        memcpy(out + 8, data, datalen);

    put16be(out + 2, nt_csum_final(nt_csum_partial(out, len)));

    *outlen = len;
    return NT_OK;
}

nt_status nt_build_arp_frame(uint8_t *out, size_t cap, size_t *outlen, const nt_arp_in *in)
{
    if (out == NULL || outlen == NULL || in == NULL)
        return NT_ERR_MALFORMED;
    if (cap < 42)
        return NT_ERR_TRUNCATED;

    memcpy(out, in->eth_dst, 6);      /* Ethernet dst */
    memcpy(out + 6, in->eth_src, 6);  /* Ethernet src */
    put16be(out + 12, NT_ETHERTYPE_ARP);

    put16be(out + 14, 0x0001);        /* htype: Ethernet */
    put16be(out + 16, NT_ETHERTYPE_IPV4);
    out[18] = 6;                      /* hlen */
    out[19] = 4;                      /* plen */
    put16be(out + 20, in->op);
    memcpy(out + 22, in->sha, 6);     /* sender hardware */
    memcpy(out + 28, in->spa, 4);     /* sender protocol */
    memcpy(out + 32, in->tha, 6);     /* target hardware */
    memcpy(out + 38, in->tpa, 4);     /* target protocol */
    *outlen = 42;
    return NT_OK;
}

nt_status nt_build_icmp6_ns(uint8_t *out, size_t cap, size_t *outlen,
                            const uint8_t src[16], const uint8_t dst[16],
                            const uint8_t target[16], const uint8_t src_ll[6])
{
    if (out == NULL || outlen == NULL || src == NULL || dst == NULL || target == NULL)
        return NT_ERR_MALFORMED;

    size_t len = 8 + 16 + (src_ll != NULL ? 8 : 0);
    if (cap < len)
        return NT_ERR_TRUNCATED;

    out[0] = 135;                     /* Type: Neighbor Solicitation */
    out[1] = 0;
    put16be(out + 2, 0);              /* checksum placeholder */
    memset(out + 4, 0, 4);            /* reserved */
    memcpy(out + 8, target, 16);
    if (src_ll != NULL) {
        out[24] = 1;                  /* option: source link-layer address */
        out[25] = 1;                  /* length in 8-byte units */
        memcpy(out + 26, src_ll, 6);
    }

    uint32_t sum = nt_csum_pseudo6(src, dst, NT_IPPROTO_ICMPV6, (uint32_t)len);
    sum = nt_csum_add(sum, out, len);
    put16be(out + 2, nt_csum_final(sum));

    *outlen = len;
    return NT_OK;
}

nt_status nt_build_icmp6_echo(uint8_t *out, size_t cap, size_t *outlen,
                              uint8_t type, uint16_t id, uint16_t seq,
                              const uint8_t *data, size_t datalen,
                              const uint8_t src[16], const uint8_t dst[16])
{
    if (out == NULL || outlen == NULL || src == NULL || dst == NULL)
        return NT_ERR_MALFORMED;
    if (datalen > 0 && data == NULL)
        return NT_ERR_MALFORMED;

    size_t len = 8 + datalen;
    if (cap < len)
        return NT_ERR_TRUNCATED;

    out[0] = type;
    out[1] = 0;
    put16be(out + 2, 0);
    put16be(out + 4, id);
    put16be(out + 6, seq);
    if (datalen > 0)
        memcpy(out + 8, data, datalen);

    uint32_t sum = nt_csum_pseudo6(src, dst, NT_IPPROTO_ICMPV6, (uint32_t)len);
    sum = nt_csum_add(sum, out, len);
    put16be(out + 2, nt_csum_final(sum));

    *outlen = len;
    return NT_OK;
}

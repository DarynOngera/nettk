#include "nt_test.h"

#include <stdint.h>

/* 20-byte IPv4 header, totlen 52, proto TCP, DF, valid header checksum 0x23c0,
 * src 10.0.1.2, dst 10.0.2.2, followed by 32 payload bytes. */
static uint8_t pkt[52] = {
    0x45, 0x00, 0x00, 0x34, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06,
    0x23, 0xc0, 0x0a, 0x00, 0x01, 0x02, 0x0a, 0x00, 0x02, 0x02,
};

int main(void)
{
    for (size_t i = 20; i < sizeof pkt; i++) { pkt[i] = 0xaa; }

    nt_ipv4 ip;
    NT_EQ_INT(nt_ipv4_decode(pkt, sizeof pkt, &ip), NT_OK);
    NT_EQ_INT(ip.ihl, 5);
    NT_EQ_INT(ip.tos, 0);
    NT_EQ_INT(ip.totlen, 52);
    NT_EQ_INT(ip.id, 1);
    NT_EQ_INT(ip.flag_df, 1);
    NT_EQ_INT(ip.flag_mf, 0);
    NT_EQ_INT(ip.frag_off, 0);
    NT_EQ_INT(ip.ttl, 64);
    NT_EQ_INT(ip.proto, 6);
    NT_EQ_INT(ip.src, 0x0a000102u);
    NT_EQ_INT(ip.dst, 0x0a000202u);
    NT_EQ_INT(ip.is_fragment, 0);
    NT_EQ_INT(ip.has_l4, 1);
    NT_EQ_INT(ip.options.len, 0);
    NT_EQ_INT(ip.payload.len, 32);
    NT_CHECK(ip.payload.data == pkt + 20);
    NT_EQ_INT(ip.hdr_csum, NT_CSUM_VALID);

    /* first fragment: MF set, offset 0 -> has_l4 still true */
    uint8_t f[52];
    memcpy(f, pkt, sizeof f);
    f[6] = 0x20; f[7] = 0x00; /* MF */
    NT_EQ_INT(nt_ipv4_decode(f, sizeof f, &ip), NT_OK);
    NT_EQ_INT(ip.is_fragment, 1);
    NT_EQ_INT(ip.flag_mf, 1);
    NT_EQ_INT(ip.has_l4, 1);

    /* later fragment: offset != 0 -> no L4 */
    memcpy(f, pkt, sizeof f);
    f[6] = 0x00; f[7] = 0x01; /* frag_off = 1 */
    NT_EQ_INT(nt_ipv4_decode(f, sizeof f, &ip), NT_OK);
    NT_EQ_INT(ip.is_fragment, 1);
    NT_EQ_INT(ip.frag_off, 1);
    NT_EQ_INT(ip.has_l4, 0);

    /* errors */
    NT_EQ_INT(nt_ipv4_decode(pkt, 10, &ip), NT_ERR_TRUNCATED);

    memcpy(f, pkt, sizeof f); f[0] = 0x55;
    NT_EQ_INT(nt_ipv4_decode(f, sizeof f, &ip), NT_ERR_MALFORMED); /* version 5 */

    memcpy(f, pkt, sizeof f); f[0] = 0x44;
    NT_EQ_INT(nt_ipv4_decode(f, sizeof f, &ip), NT_ERR_MALFORMED); /* IHL 4 */

    memcpy(f, pkt, sizeof f); f[2] = 0x00; f[3] = 0x10; /* totlen 16 < 20 */
    NT_EQ_INT(nt_ipv4_decode(f, sizeof f, &ip), NT_ERR_MALFORMED);

    memcpy(f, pkt, sizeof f); f[2] = 0x01; f[3] = 0x00; /* totlen 256 > len */
    NT_EQ_INT(nt_ipv4_decode(f, sizeof f, &ip), NT_ERR_TRUNCATED);

    /* IHL larger than the supplied buffer */
    memcpy(f, pkt, sizeof f); f[0] = 0x4f; /* IHL 15 -> 60 bytes */
    NT_EQ_INT(nt_ipv4_decode(f, sizeof f, &ip), NT_ERR_TRUNCATED);

    /* options slice: IHL 6 -> 4 option bytes */
    memcpy(f, pkt, sizeof f); f[0] = 0x46; f[2] = 0x00; f[3] = 0x18; /* totlen 24 */
    NT_EQ_INT(nt_ipv4_decode(f, 24, &ip), NT_OK);
    NT_EQ_INT(ip.ihl, 6);
    NT_EQ_INT(ip.options.len, 4);
    NT_EQ_INT(ip.payload.len, 0);

    NT_DONE();
}

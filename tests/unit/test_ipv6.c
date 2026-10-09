#include "nt_test.h"

#include <stdint.h>

/* IPv6 header: payload_len 15, next=ICMPv6(58), hlim 64, fd00::1:2 -> fd00::2:2 */
static uint8_t pkt[55] = {
    0x60, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x3a, 0x40,
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02,
};

int main(void)
{
    for (size_t i = 40; i < sizeof pkt; i++) { pkt[i] = 0xbb; }

    const uint8_t src[16] = {
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
    };
    const uint8_t dst[16] = {
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02,
    };

    nt_ipv6 ip;
    NT_EQ_INT(nt_ipv6_decode(pkt, sizeof pkt, &ip), NT_OK);
    NT_EQ_INT(ip.payload_len, 15);
    NT_EQ_INT(ip.next_hdr, 58);
    NT_EQ_INT(ip.hop_limit, 64);
    NT_EQ_MEM(ip.src, src, 16);
    NT_EQ_MEM(ip.dst, dst, 16);
    NT_EQ_INT(ip.payload.len, 15);
    NT_CHECK(ip.payload.data == pkt + 40);
    NT_EQ_INT(ip.is_fragment, 0);

    /* errors */
    NT_EQ_INT(nt_ipv6_decode(pkt, 20, &ip), NT_ERR_TRUNCATED);

    uint8_t f[55];
    memcpy(f, pkt, sizeof f); f[0] = 0x40; /* version 4 */
    NT_EQ_INT(nt_ipv6_decode(f, sizeof f, &ip), NT_ERR_MALFORMED);

    memcpy(f, pkt, sizeof f); f[4] = 0x00; f[5] = 0x20; /* payload_len 32 > 15 available */
    NT_EQ_INT(nt_ipv6_decode(f, sizeof f, &ip), NT_ERR_TRUNCATED);

    /* extension header (hop-by-hop) is unsupported at the frame level */
    memcpy(f, pkt, sizeof f); f[6] = 0; /* next = HOPOPTS */
    NT_EQ_INT(nt_ipv6_decode(f, sizeof f, &ip), NT_OK);
    NT_EQ_INT(ip.next_hdr, 0);

    NT_DONE();
}

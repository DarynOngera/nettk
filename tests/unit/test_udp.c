#include "nt_test.h"

#include <stdint.h>

/* Real UDP/DNS query from fixtures/basic.pcap: 10.0.1.2:53000 -> 10.0.2.53:53. */
static const uint8_t seg[37] = {
    0xcf, 0x08, 0x00, 0x35,             /* 53000 -> 53 */
    0x00, 0x25,                         /* length 37 */
    0x8a, 0xd2,                         /* checksum */
    0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
    0x00, 0x00, 0x01, 0x00, 0x01,
};

static const nt_pseudo ph4 = {.family = 4, .src4 = 0x0a000102u, .dst4 = 0x0a000235u};

int main(void)
{
    nt_udp u;

    NT_EQ_INT(nt_udp_decode(seg, sizeof seg, &ph4, &u), NT_OK);
    NT_EQ_INT(u.sport, 53000);
    NT_EQ_INT(u.dport, 53);
    NT_EQ_INT(u.len, 37);
    NT_EQ_INT(u.csum, 0x8ad2);
    NT_EQ_INT(u.payload.len, 29);
    NT_CHECK(u.payload.data == seg + 8);
    NT_EQ_INT(u.csum_state, NT_CSUM_VALID);

    NT_EQ_INT(nt_udp_decode(seg, sizeof seg, NULL, &u), NT_OK);
    NT_EQ_INT(u.csum_state, NT_CSUM_NOT_CHECKED);

    /* IPv4 UDP checksum 0 means "not computed" (RFC 768) */
    uint8_t z[37];
    memcpy(z, seg, sizeof z);
    z[6] = 0x00; z[7] = 0x00;
    NT_EQ_INT(nt_udp_decode(z, sizeof z, &ph4, &u), NT_OK);
    NT_EQ_INT(u.csum_state, NT_CSUM_NOT_CHECKED);

    /* wrong checksum */
    z[6] = 0x12; z[7] = 0x34;
    NT_EQ_INT(nt_udp_decode(z, sizeof z, &ph4, &u), NT_OK);
    NT_EQ_INT(u.csum_state, NT_CSUM_INVALID);

    /* errors */
    NT_EQ_INT(nt_udp_decode(seg, 4, &ph4, &u), NT_ERR_TRUNCATED);

    memcpy(z, seg, sizeof z); z[4] = 0x00; z[5] = 0x04; /* length 4 < 8 */
    NT_EQ_INT(nt_udp_decode(z, sizeof z, &ph4, &u), NT_ERR_MALFORMED);

    memcpy(z, seg, sizeof z); z[4] = 0x00; z[5] = 0xff; /* length 255 > supplied */
    NT_EQ_INT(nt_udp_decode(z, sizeof z, &ph4, &u), NT_ERR_TRUNCATED);

    NT_DONE();
}

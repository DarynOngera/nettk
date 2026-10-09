#include "nt_test.h"

#include <stdint.h>

/* Real ICMPv6 echo request from fixtures/ipv6.pcap, fd00::1:2 -> fd00::2:2. */
static const uint8_t msg[15] = {
    0x80, 0x00, 0xff, 0x62,
    0x12, 0x34, 0x00, 0x01,
    'v', '6', '-', 'p', 'i', 'n', 'g',
};

static const nt_pseudo ph6 = {
    .family = 6,
    .src6 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02},
    .dst6 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02},
};

/* Real NDP neighbour solicitation header + target, from fixtures/ipv6.pcap. */
static const uint8_t ns[24] = {
    0x87, 0x00, 0x77, 0x13, 0x00, 0x00, 0x00, 0x00,
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02,
};

int main(void)
{
    nt_icmp ic;

    NT_EQ_INT(nt_icmp6_decode(msg, sizeof msg, &ph6, &ic), NT_OK);
    NT_EQ_INT(ic.type, 128);
    NT_EQ_INT(ic.code, 0);
    NT_EQ_INT(ic.csum, 0xff62);
    NT_EQ_INT(ic.rest.len, 11);
    NT_EQ_INT(ic.has_target, 0);
    NT_EQ_INT(ic.csum_state, NT_CSUM_VALID);

    /* neighbour solicitation: target address is decoded, csum skipped here */
    const uint8_t target[16] = {
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02,
    };
    NT_EQ_INT(nt_icmp6_decode(ns, sizeof ns, NULL, &ic), NT_OK);
    NT_EQ_INT(ic.type, 135);
    NT_EQ_INT(ic.has_target, 1);
    NT_EQ_MEM(ic.target, target, 16);
    NT_EQ_INT(nt_icmp6_decode(ns, 20, NULL, &ic), NT_ERR_TRUNCATED);

    NT_EQ_INT(nt_icmp6_decode(msg, sizeof msg, NULL, &ic), NT_OK);
    NT_EQ_INT(ic.csum_state, NT_CSUM_NOT_CHECKED);

    uint8_t bad[15];
    memcpy(bad, msg, sizeof bad);
    bad[2] ^= 0xff;
    NT_EQ_INT(nt_icmp6_decode(bad, sizeof bad, &ph6, &ic), NT_OK);
    NT_EQ_INT(ic.csum_state, NT_CSUM_INVALID);

    NT_EQ_INT(nt_icmp6_decode(msg, 4, &ph6, &ic), NT_ERR_TRUNCATED);

    NT_DONE();
}

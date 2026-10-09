#include "nt_test.h"

#include <stdint.h>

/* Real ICMP echo request from fixtures/basic.pcap: type 8, code 0, "phase0-ping". */
static const uint8_t msg[19] = {
    0x08, 0x00, 0xb0, 0xdf,
    0x12, 0x34, 0x00, 0x01,
    'p', 'h', 'a', 's', 'e', '0', '-', 'p', 'i', 'n', 'g',
};

int main(void)
{
    nt_icmp ic;

    NT_EQ_INT(nt_icmp_decode(msg, sizeof msg, &ic), NT_OK);
    NT_EQ_INT(ic.type, 8);
    NT_EQ_INT(ic.code, 0);
    NT_EQ_INT(ic.csum, 0xb0df);
    NT_EQ_INT(ic.rest.len, 15);
    NT_CHECK(ic.rest.data == msg + 4);
    NT_EQ_INT(ic.csum_state, NT_CSUM_VALID);

    uint8_t bad[19];
    memcpy(bad, msg, sizeof bad);
    bad[2] ^= 0xff;
    NT_EQ_INT(nt_icmp_decode(bad, sizeof bad, &ic), NT_OK);
    NT_EQ_INT(ic.csum_state, NT_CSUM_INVALID);

    NT_EQ_INT(nt_icmp_decode(msg, 5, &ic), NT_ERR_TRUNCATED);

    NT_DONE();
}

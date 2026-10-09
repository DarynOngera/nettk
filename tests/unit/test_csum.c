#include "nt_test.h"

#include <stdint.h>

int main(void)
{
    /* empty and all-zero/all-ones */
    NT_EQ_INT(nt_csum_final(nt_csum_partial("", 0)), 0xffff);
    const uint8_t zero[2] = {0x00, 0x00};
    NT_EQ_INT(nt_csum_final(nt_csum_partial(zero, 2)), 0xffff);
    const uint8_t ones[2] = {0xff, 0xff};
    NT_EQ_INT(nt_csum_final(nt_csum_partial(ones, 2)), 0x0000);

    /* complements of a single word */
    const uint8_t w1[2] = {0x12, 0x34};
    NT_EQ_INT(nt_csum_final(nt_csum_partial(w1, 2)), 0xedcb);
    const uint8_t w2[4] = {0x12, 0x34, 0x56, 0x78};
    NT_EQ_INT(nt_csum_final(nt_csum_partial(w2, 4)), 0x9753); /* ~0x68ac */

    /* odd trailing byte is the high half of a zero-padded word */
    const uint8_t odd[3] = {0x12, 0x34, 0x56};
    NT_EQ_INT(nt_csum_final(nt_csum_partial(odd, 3)), 0x97cb); /* ~0x6834 */

    /* add() composes partial sums */
    uint32_t s = nt_csum_partial(w1, 2);
    s = nt_csum_add(s, w1, 2);
    NT_EQ_INT(nt_csum_final(s), 0xdb97); /* ~(0x1234+0x1234) */

    /* IPv4 pseudo-header (RFC 793 style): src+dst+proto+len, host-order words */
    NT_EQ_INT(nt_csum_pseudo4(0x0a000102u, 0x0a000202u, 6, 20), 0x171e);

    /* IPv6 pseudo-header: src16 + dst16 + len + nxt */
    const uint8_t z16[16] = {0};
    NT_EQ_INT(nt_csum_pseudo6(z16, z16, 58, 8), 66);

    NT_DONE();
}

#include "nt_test.h"

#include <stdint.h>

/* A real TCP SYN segment (40 bytes incl. 20 bytes of options) captured in
 * fixtures/basic.pcap; source 10.0.1.2 -> 10.0.2.2, checksum 0x7015. */
static const uint8_t seg[40] = {
    0x9c, 0x40, 0x00, 0x50,             /* 40000 -> 80 */
    0x00, 0x00, 0x03, 0xe8,             /* seq 1000 */
    0x00, 0x00, 0x00, 0x00,             /* ack 0 */
    0xa0, 0x02,                         /* data_off 10, SYN */
    0x20, 0x00,                         /* window 8192 */
    0x70, 0x15,                         /* checksum */
    0x00, 0x00,                         /* urgent */
    0x02, 0x04, 0x05, 0xb4,             /* MSS 1460 */
    0x04, 0x02,                         /* SACK permitted */
    0x08, 0x0a, 0x00, 0x00, 0x00, 0x6f, /* Timestamp */
    0x00, 0x00, 0x00, 0x00,
    0x01,                               /* NOP */
    0x03, 0x03, 0x07,                   /* Window scale 7 */
};

static const nt_pseudo ph4 = {.family = 4, .src4 = 0x0a000102u, .dst4 = 0x0a000202u};

int main(void)
{
    nt_tcp t;

    NT_EQ_INT(nt_tcp_decode(seg, sizeof seg, &ph4, &t), NT_OK);
    NT_EQ_INT(t.sport, 40000);
    NT_EQ_INT(t.dport, 80);
    NT_EQ_INT(t.seq, 1000);
    NT_EQ_INT(t.ack, 0);
    NT_EQ_INT(t.data_off, 10);
    NT_EQ_INT(t.flags, 0x0002);
    NT_EQ_INT(t.window, 8192);
    NT_EQ_INT(t.csum, 0x7015);
    NT_EQ_INT(t.urg, 0);
    NT_EQ_INT(t.options.len, 20);
    NT_EQ_INT(t.payload.len, 0);
    NT_EQ_INT(t.mss, 1460);
    NT_EQ_INT(t.sack_ok, 1);
    NT_EQ_INT(t.has_ts, 1);
    NT_EQ_INT(t.ts_val, 111);
    NT_EQ_INT(t.ts_ecr, 0);
    NT_EQ_INT(t.wscale, 7);
    NT_EQ_INT(t.csum_state, NT_CSUM_VALID);

    /* NULL pseudo-header skips verification */
    NT_EQ_INT(nt_tcp_decode(seg, sizeof seg, NULL, &t), NT_OK);
    NT_EQ_INT(t.csum_state, NT_CSUM_NOT_CHECKED);

    /* wrong checksum is detected */
    uint8_t bad[40];
    memcpy(bad, seg, sizeof bad);
    bad[16] ^= 0xff;
    NT_EQ_INT(nt_tcp_decode(bad, sizeof bad, &ph4, &t), NT_OK);
    NT_EQ_INT(t.csum_state, NT_CSUM_INVALID);

    /* header-only segment (data offset 5) has no options and defaults */
    uint8_t hdr[20];
    memcpy(hdr, seg, sizeof hdr);
    hdr[12] = 0x50; /* data_off = 5 */
    NT_EQ_INT(nt_tcp_decode(hdr, sizeof hdr, &ph4, &t), NT_OK);
    NT_EQ_INT(t.options.len, 0);
    NT_EQ_INT(t.payload.len, 0);
    NT_EQ_INT(t.mss, -1);
    NT_EQ_INT(t.wscale, -1);
    NT_EQ_INT(t.sack_ok, 0);
    NT_EQ_INT(t.has_ts, 0);

    /* data offset below 5 */
    memcpy(bad, seg, sizeof bad); bad[12] = 0x10;
    NT_EQ_INT(nt_tcp_decode(bad, sizeof bad, &ph4, &t), NT_ERR_MALFORMED);

    /* data offset claims more header than supplied */
    NT_EQ_INT(nt_tcp_decode(seg, 30, &ph4, &t), NT_ERR_TRUNCATED);

    /* option with a length past the end of the option area */
    uint8_t opt[24] = {0};
    opt[12] = 0x60; /* data_off = 6 -> 4 option bytes */
    opt[20] = 0x02; opt[21] = 0x05; opt[22] = 0x00; opt[23] = 0x00;
    NT_EQ_INT(nt_tcp_decode(opt, sizeof opt, &ph4, &t), NT_ERR_TRUNCATED);

    /* option kind >= 2 with a zero length byte is malformed */
    memcpy(opt, seg, sizeof opt);
    opt[12] = 0x60;
    opt[20] = 0x02; opt[21] = 0x00;
    NT_EQ_INT(nt_tcp_decode(opt, sizeof opt, &ph4, &t), NT_ERR_MALFORMED);

    /* truncated below the minimum header */
    NT_EQ_INT(nt_tcp_decode(seg, 10, &ph4, &t), NT_ERR_TRUNCATED);

    NT_DONE();
}

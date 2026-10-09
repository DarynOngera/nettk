#include "nt_test.h"

#include <stdint.h>

/* 02:00:00:00:01:02 -> 02:00:00:00:02:02, type 0x0800 */
static const uint8_t f_ipv4[14] = {
    0x02, 0x00, 0x00, 0x00, 0x02, 0x02,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
    0x08, 0x00,
};

static const uint8_t f_arp[14] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
    0x08, 0x06,
};

/* 802.3 length field, below 0x0600 */
static const uint8_t f_8023[14] = {
    0x02, 0x00, 0x00, 0x00, 0x02, 0x02,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
    0x00, 0x2a,
};

/* runt: 10 bytes, shorter than an Ethernet header */
static const uint8_t f_runt[10] = {
    0x02, 0x00, 0x00, 0x00, 0x02, 0x02,
    0x02, 0x00, 0x00, 0x00,
};

/* one 802.1Q tag: PCP 3, VID 50, inner 0x0800 */
static const uint8_t f_vlan1[18] = {
    0x02, 0x00, 0x00, 0x00, 0x02, 0x02,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
    0x81, 0x00,
    0x60, 0x32, /* pcp=3, dei=0, vid=50 */
    0x08, 0x00,
};

/* 802.1ad outer (0x88a8, VID 100) + 802.1Q inner (0x8100, VID 200), inner 0x0800 */
static const uint8_t f_vlan2[22] = {
    0x02, 0x00, 0x00, 0x00, 0x02, 0x02,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
    0x88, 0xa8, 0x00, 0x64,
    0x81, 0x00, 0x00, 0xc8,
    0x08, 0x00,
};

/* three stacked tags: unsupported */
static const uint8_t f_vlan3[26] = {
    0x02, 0x00, 0x00, 0x00, 0x02, 0x02,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
    0x81, 0x00, 0x00, 0x01,
    0x81, 0x00, 0x00, 0x02,
    0x81, 0x00, 0x00, 0x03,
    0x08, 0x00,
};

/* tag declared but cut before the TCI completes */
static const uint8_t f_vlan_trunc[15] = {
    0x02, 0x00, 0x00, 0x00, 0x02, 0x02,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
    0x81, 0x00, 0x00,
};

static void check_ok(const uint8_t *f, size_t len, uint16_t etype)
{
    nt_eth_hdr e;
    nt_vlan v;
    NT_EQ_INT(nt_eth_decode(f, len, &e, &v), NT_OK);
    NT_EQ_INT(e.ethertype, etype);
    NT_EQ_INT(v.inner_ethertype, etype);
    NT_EQ_INT(v.l3_off, 14);
    NT_EQ_INT(v.count, 0);
}

int main(void)
{
    nt_eth_hdr e;
    nt_vlan v;

    check_ok(f_ipv4, sizeof f_ipv4, 0x0800);
    check_ok(f_arp, sizeof f_arp, 0x0806);

    /* addresses copied in wire order */
    NT_EQ_INT(nt_eth_decode(f_ipv4, sizeof f_ipv4, &e, &v), NT_OK);
    const uint8_t want_dst[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x02};
    const uint8_t want_src[6] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x02};
    NT_EQ_MEM(e.dst, want_dst, 6);
    NT_EQ_MEM(e.src, want_src, 6);

    /* runt */
    NT_EQ_INT(nt_eth_decode(f_runt, sizeof f_runt, &e, &v), NT_ERR_TRUNCATED);

    /* 802.3 length: unsupported but the Ethernet header is filled */
    NT_EQ_INT(nt_eth_decode(f_8023, sizeof f_8023, &e, &v), NT_ERR_UNSUPPORTED);
    NT_EQ_INT(e.ethertype, 0x002a);
    NT_EQ_INT(v.l3_off, 14);

    /* single tag */
    NT_EQ_INT(nt_eth_decode(f_vlan1, sizeof f_vlan1, &e, &v), NT_OK);
    NT_EQ_INT(e.ethertype, 0x8100);
    NT_EQ_INT(v.count, 1);
    NT_EQ_INT(v.tag[0].tpid, 0x8100);
    NT_EQ_INT(v.tag[0].pcp, 3);
    NT_EQ_INT(v.tag[0].dei, 0);
    NT_EQ_INT(v.tag[0].vid, 50);
    NT_EQ_INT(v.inner_ethertype, 0x0800);
    NT_EQ_INT(v.l3_off, 18);

    /* double tag, outer first */
    NT_EQ_INT(nt_eth_decode(f_vlan2, sizeof f_vlan2, &e, &v), NT_OK);
    NT_EQ_INT(e.ethertype, 0x88a8);
    NT_EQ_INT(v.count, 2);
    NT_EQ_INT(v.tag[0].tpid, 0x88a8);
    NT_EQ_INT(v.tag[0].vid, 100);
    NT_EQ_INT(v.tag[1].tpid, 0x8100);
    NT_EQ_INT(v.tag[1].vid, 200);
    NT_EQ_INT(v.inner_ethertype, 0x0800);
    NT_EQ_INT(v.l3_off, 22);

    /* third tag */
    NT_EQ_INT(nt_eth_decode(f_vlan3, sizeof f_vlan3, &e, &v), NT_ERR_UNSUPPORTED);
    NT_EQ_INT(v.count, 2);

    /* truncated tag */
    NT_EQ_INT(nt_eth_decode(f_vlan_trunc, sizeof f_vlan_trunc, &e, &v), NT_ERR_TRUNCATED);

    NT_DONE();
}

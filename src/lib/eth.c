#include "nettk.h"

#include <string.h>

#define NT_ETH_HDR_LEN   14
#define NT_VLAN_TPID_1   0x8100u
#define NT_VLAN_TPID_2   0x88a8u
#define NT_ETHERTYPE_MIN 0x0600u /* below this the 12:2 field is an 802.3 length */

nt_status nt_eth_decode(const uint8_t *buf, size_t len, nt_eth_hdr *eth, nt_vlan *vlan)
{
    memset(eth, 0, sizeof *eth);
    memset(vlan, 0, sizeof *vlan);

    if (!need(len, 0, NT_ETH_HDR_LEN)) {
        return NT_ERR_TRUNCATED;
    }

    memcpy(eth->dst, buf, 6);
    memcpy(eth->src, buf + 6, 6);
    eth->ethertype = rd16be(buf, 12);

    uint16_t et = eth->ethertype;
    vlan->inner_ethertype = et;
    vlan->l3_off = NT_ETH_HDR_LEN;

    if (et < NT_ETHERTYPE_MIN) {
        return NT_ERR_UNSUPPORTED; /* 802.3 length field */
    }

    /* The 802.1Q tag shares offset 12: TPID at 12, TCI at 14, inner type at 16. */
    size_t off = 14;
    while (et == NT_VLAN_TPID_1 || et == NT_VLAN_TPID_2) {
        if (vlan->count >= 2) {
            vlan->inner_ethertype = et;
            vlan->l3_off = off;
            return NT_ERR_UNSUPPORTED; /* more than two stacked tags */
        }
        if (!need(len, off, 4)) { /* TCI (2) + inner ethertype (2) */
            return NT_ERR_TRUNCATED;
        }
        uint16_t tci = rd16be(buf, off);
        nt_vlan_tag *t = &vlan->tag[vlan->count];
        t->tpid = et;
        t->pcp = (uint8_t)((tci >> 13) & 0x7u);
        t->dei = (uint8_t)((tci >> 12) & 0x1u);
        t->vid = (uint16_t)(tci & 0x0fffu);
        vlan->count++;

        et = rd16be(buf, off + 2);
        off += 4;
    }

    vlan->inner_ethertype = et;
    vlan->l3_off = off;
    return NT_OK;
}

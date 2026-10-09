#include "nettk.h"

#include <string.h>

#define NT_ARP_LEN 28

nt_status nt_arp_decode(const uint8_t *buf, size_t len, nt_arp *out)
{
    memset(out, 0, sizeof *out);
    if (!need(len, 0, NT_ARP_LEN)) {
        return NT_ERR_TRUNCATED;
    }

    out->htype = rd16be(buf, 0);
    out->ptype = rd16be(buf, 2);
    out->hlen = rd8(buf, 4);
    out->plen = rd8(buf, 5);
    out->op = rd16be(buf, 6);

    if (out->htype != 1 || out->ptype != NT_ETHERTYPE_IPV4 ||
        out->hlen != 6 || out->plen != 4) {
        return NT_ERR_UNSUPPORTED; /* only Ethernet/IPv4 ARP */
    }

    memcpy(out->sha, buf + 8, 6);
    memcpy(out->spa, buf + 14, 4);
    memcpy(out->tha, buf + 18, 6);
    memcpy(out->tpa, buf + 24, 4);
    return NT_OK;
}

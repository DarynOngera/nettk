#include "nt_test.h"

#include <stdint.h>

/* ARP request: who-has 10.0.1.1 tell 10.0.1.2 (Ethernet/IPv4) */
static const uint8_t arp_req[28] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
    0x0a, 0x00, 0x01, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x01, 0x01,
};

int main(void)
{
    nt_arp a;

    NT_EQ_INT(nt_arp_decode(arp_req, sizeof arp_req, &a), NT_OK);
    NT_EQ_INT(a.htype, 1);
    NT_EQ_INT(a.ptype, 0x0800);
    NT_EQ_INT(a.hlen, 6);
    NT_EQ_INT(a.plen, 4);
    NT_EQ_INT(a.op, 1);
    const uint8_t sha[6] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x02};
    const uint8_t tha[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t spa[4] = {0x0a, 0x00, 0x01, 0x02};
    const uint8_t tpa[4] = {0x0a, 0x00, 0x01, 0x01};
    NT_EQ_MEM(a.sha, sha, 6);
    NT_EQ_MEM(a.tha, tha, 6);
    NT_EQ_MEM(a.spa, spa, 4);
    NT_EQ_MEM(a.tpa, tpa, 4);

    /* truncated */
    NT_EQ_INT(nt_arp_decode(arp_req, 10, &a), NT_ERR_TRUNCATED);

    /* non-Ethernet hardware type is out of scope */
    uint8_t weird[28];
    memcpy(weird, arp_req, sizeof weird);
    weird[0] = 0x00; weird[1] = 0x06; /* htype = 6 */
    NT_EQ_INT(nt_arp_decode(weird, sizeof weird, &a), NT_ERR_UNSUPPORTED);

    NT_DONE();
}

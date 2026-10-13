#include "dhcp.h"
#include "nt_test.h"

#include <stdint.h>
#include <string.h>

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static const uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x06, 0x0a };

/* 240-byte fixed header + magic cookie. */
static size_t mk_hdr(uint8_t *b, uint8_t op, uint32_t xid, uint32_t yiaddr,
                     const uint8_t ch[6])
{
    memset(b, 0, 240);
    b[0] = op; b[1] = 1; b[2] = 6; b[3] = 0;
    wr32(b + 4, xid);
    wr32(b + 16, yiaddr);
    memcpy(b + 28, ch, 6);
    wr32(b + 236, NT_DHCP_MAGIC);
    return 240;
}

static size_t add_opt(uint8_t *b, size_t off, uint8_t code, const uint8_t *d, uint8_t len)
{
    b[off++] = code;
    b[off++] = len;
    if (len > 0) {
        memcpy(b + off, d, len);
        off += len;
    }
    return off;
}

static size_t add_u8(uint8_t *b, size_t off, uint8_t code, uint8_t v)
{
    return add_opt(b, off, code, &v, 1);
}

static size_t add_u32(uint8_t *b, size_t off, uint8_t code, uint32_t v)
{
    uint8_t t[4];
    wr32(t, v);
    return add_opt(b, off, code, t, 4);
}

int main(void)
{
    uint8_t msg[512];
    nt_dhcp m;
    const uint32_t xid = 0xdeadbeefu;

    /* ---- a valid OFFER round trip ------------------------------------ */
    size_t off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u /* 10.0.6.100 */, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    off = add_u32(msg, off, NT_DHCP_OPT_SERVER_ID, 0x0a000601u /* 10.0.6.1 */);
    off = add_u32(msg, off, NT_DHCP_OPT_LEASE_TIME, 3600);
    off = add_u32(msg, off, NT_DHCP_OPT_MASK, 0xffffff00u);
    {
        uint8_t routers[4] = { 0x0a, 0x00, 0x06, 0x01 };
        off = add_opt(msg, off, NT_DHCP_OPT_ROUTER, routers, 4);
    }
    msg[off++] = NT_DHCP_OPT_END;

    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_OK);
    NT_EQ_INT(m.op, NT_DHCP_BOOTREPLY);
    NT_EQ_INT(m.htype, 1);
    NT_EQ_INT(m.hlen, 6);
    NT_EQ_INT(m.xid, xid);
    NT_EQ_INT(m.yiaddr, 0x0a000664u);
    NT_EQ_INT(m.has_msg_type, 1);
    NT_EQ_INT(m.msg_type, NT_DHCP_OFFER);
    NT_EQ_INT(m.has_server_id, 1);
    NT_EQ_INT(m.server_id, 0x0a000601u);
    NT_EQ_INT(m.has_lease, 1);
    NT_EQ_INT(m.lease_time, 3600);
    NT_EQ_INT(m.has_mask, 1);
    NT_EQ_INT(m.mask, 0xffffff00u);
    NT_EQ_INT(m.has_router, 1);
    NT_EQ_INT(m.nrouter, 1);
    NT_EQ_INT(m.router[0], 0x0a000601u);
    NT_EQ_INT(m.broadcast, 0);

    NT_EQ_INT(nt_dhcp_match_offer(&m, xid, mac), NT_MATCH);
    NT_EQ_INT(nt_dhcp_match_offer(&m, xid + 1, mac), NT_NO_MATCH);
    NT_EQ_INT(nt_dhcp_match_offer(&m, xid, (const uint8_t[6]){ 2, 0, 0, 0, 6, 0xff }), NT_NO_MATCH);
    NT_EQ_INT(nt_dhcp_match_ack(&m, xid, mac, m.yiaddr), NT_NO_MATCH); /* it is an OFFER */

    /* ACK sanity: change the message type */
    msg[240 + 2] = NT_DHCP_ACK;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_OK);
    NT_EQ_INT(nt_dhcp_match_ack(&m, xid, mac, 0x0a000664u), NT_MATCH);
    NT_EQ_INT(nt_dhcp_match_ack(&m, xid, mac, 0x0a000665u), NT_NO_MATCH);
    NT_EQ_INT(nt_dhcp_match_offer(&m, xid, mac), NT_NO_MATCH);

    /* NAK: yiaddr 0, no yiaddr requirement */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_NAK);
    off = add_u32(msg, off, NT_DHCP_OPT_SERVER_ID, 0x0a000601u);
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_OK);
    NT_EQ_INT(nt_dhcp_match_nak(&m, xid, mac), NT_MATCH);
    NT_EQ_INT(nt_dhcp_match_offer(&m, xid, mac), NT_NO_MATCH);

    /* ---- hostile / malformed ------------------------------------------ */
    NT_EQ_INT(nt_dhcp_decode(msg, 200, &m), NT_ERR_TRUNCATED);

    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    msg[236] = 0; /* wrong cookie */
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    /* no END */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    /* option length past the end */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    msg[off++] = NT_DHCP_OPT_SERVER_ID; msg[off++] = 4; /* claims 4, none follow */
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    /* repeated option 53 */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    /* option 53 with length 2 */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    msg[off++] = NT_DHCP_OPT_MSG_TYPE; msg[off++] = 2; msg[off++] = 2; msg[off++] = 0;
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    /* option 53 with an unknown value */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, 99);
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    /* option 52 (overload) is UNSUPPORTED */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    off = add_u8(msg, off, NT_DHCP_OPT_OVERLOAD, 1);
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_UNSUPPORTED);

    /* htype 1 with hlen 7, and hlen 17 */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    msg[2] = 7;
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);
    msg[2] = 17;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    /* router with length 5, server id with length 3 */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    {
        uint8_t r5[5] = { 1, 2, 3, 4, 5 };
        off = add_opt(msg, off, NT_DHCP_OPT_ROUTER, r5, 5);
    }
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    {
        uint8_t s3[3] = { 10, 0, 6 };
        off = add_opt(msg, off, NT_DHCP_OPT_SERVER_ID, s3, 3);
    }
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_ERR_MALFORMED);

    /* PAD runs fill the packet; END still required */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    for (int i = 0; i < 8; i++)
        msg[off++] = 0;
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_OK);

    /* free text is escaped, not trusted */
    off = mk_hdr(msg, NT_DHCP_BOOTREPLY, xid, 0x0a000664u, mac);
    off = add_u8(msg, off, NT_DHCP_OPT_MSG_TYPE, NT_DHCP_OFFER);
    {
        uint8_t hostile[6] = { 'h', 'i', 0x00, '\n', '`', ';' };
        off = add_opt(msg, off, NT_DHCP_OPT_HOSTNAME, hostile, 6);
    }
    msg[off++] = NT_DHCP_OPT_END;
    NT_EQ_INT(nt_dhcp_decode(msg, off, &m), NT_OK);
    NT_EQ_INT(m.has_hostname, 1);
    NT_CHECK(strcmp(m.hostname, "hi\\000\\012`;") == 0);

    /* ---- builder: DISCOVER, padded to >= 300 ------------------------- */
    nt_dhcp_opt opts[3];
    memset(opts, 0, sizeof opts);
    opts[0].code = NT_DHCP_OPT_MSG_TYPE; opts[0].len = 1; opts[0].data[0] = NT_DHCP_DISCOVER;
    opts[1].code = NT_DHCP_OPT_PARAM_LIST; opts[1].len = 3;
    opts[1].data[0] = 1; opts[1].data[1] = 3; opts[1].data[2] = 6;
    opts[2].code = NT_DHCP_OPT_MAX_MSG_SIZE; opts[2].len = 2;
    opts[2].data[0] = 0x05; opts[2].data[1] = 0xdc; /* 1500 */

    nt_dhcp_out o;
    memset(&o, 0, sizeof o);
    o.op = NT_DHCP_BOOTREQUEST; o.htype = 1; o.hlen = 6;
    o.xid = 0x12345678u;
    o.flags = NT_DHCP_FLAG_BROADCAST;
    memcpy(o.chaddr, mac, 6);
    o.opts = opts; o.nopts = 3;

    uint8_t d[512];
    size_t dlen = 0;
    NT_EQ_INT(nt_dhcp_build(&o, d, sizeof d, &dlen), NT_OK);
    NT_CHECK(dlen >= NT_DHCP_MIN_SEND);
    NT_EQ_INT(nt_dhcp_decode(d, dlen, &m), NT_OK);
    NT_EQ_INT(m.msg_type, NT_DHCP_DISCOVER);
    NT_EQ_INT(m.xid, 0x12345678u);
    NT_EQ_INT(m.broadcast, 1);
    NT_EQ_MEM(m.chaddr, mac, 6);
    NT_EQ_INT(m.has_msg_type, 1);

    /* builder refuses a short cap */
    NT_EQ_INT(nt_dhcp_build(&o, d, 100, &dlen), NT_ERR_TRUNCATED);

    /* ---- full frame round trip through the decode library ------------- */
    uint8_t frame[600];
    size_t flen = 0;
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    NT_EQ_INT(nt_build_eth_ipv4_udp(frame, sizeof frame, &flen,
                                    mac, bcast, 0u, 0xffffffffu,
                                    NT_DHCP_CLIENT_PORT, NT_DHCP_SERVER_PORT,
                                    d, dlen), NT_OK);

    nt_packet pkt;
    NT_EQ_INT(nt_decode_frame(frame, flen, &pkt), NT_OK);
    NT_EQ_INT(pkt.has_udp, 1);
    NT_EQ_INT(pkt.udp.sport, NT_DHCP_CLIENT_PORT);
    NT_EQ_INT(pkt.udp.dport, NT_DHCP_SERVER_PORT);
    NT_EQ_INT(pkt.udp.csum_state, NT_CSUM_VALID);
    NT_EQ_INT(pkt.ip4.hdr_csum, NT_CSUM_VALID);
    NT_EQ_INT(nt_dhcp_decode(pkt.udp.payload.data, pkt.udp.payload.len, &m), NT_OK);
    NT_EQ_INT(m.msg_type, NT_DHCP_DISCOVER);

    NT_DONE();
}

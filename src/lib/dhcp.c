/*
 * DHCP (BOOTP) codec, builders and matchers (phase 6, M19).
 *
 * Pure: no I/O, no allocation, no globals. Every read is bounds-checked with
 * need() before it happens. See docs/phase6.md for the byte layout and the
 * per-option rule set (rules 35, 36, 37, 38 in docs/phase4-6-prompt.md).
 */
#include "dhcp.h"

#include <string.h>

static uint16_t rd16(const uint8_t *b, size_t off) { return rd16be(b, off); }
static uint32_t rd32(const uint8_t *b, size_t off) { return rd32be(b, off); }

static void put16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Escaped copy of untrusted free text: printable ASCII verbatim, everything
 * else as \DDD (RFC 1035-style). Always NUL-terminated; truncates to fit cap. */
static void escape_into(const uint8_t *s, size_t n, char *out, size_t cap)
{
    size_t o = 0;
    if (cap == 0)
        return;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        uint8_t c = s[i];
        if (c == '\\' || (c >= 0x20 && c < 0x7f)) {
            if (o + 2 >= cap)
                break;
            out[o++] = (char)c;
        } else {
            if (o + 4 >= cap)
                break;
            out[o++] = '\\';
            out[o++] = (char)('0' + (c >> 6));
            out[o++] = (char)('0' + ((c >> 3) & 7));
            out[o++] = (char)('0' + (c & 7));
        }
    }
    out[o] = '\0';
}

const char *nt_dhcp_op_str(uint8_t op)
{
    switch (op) {
    case NT_DHCP_BOOTREQUEST: return "REQUEST";
    case NT_DHCP_BOOTREPLY:   return "REPLY";
    default:                  return "?";
    }
}

const char *nt_dhcp_msg_type_str(uint8_t type)
{
    switch (type) {
    case NT_DHCP_DISCOVER: return "DISCOVER";
    case NT_DHCP_OFFER:    return "OFFER";
    case NT_DHCP_REQUEST:  return "REQUEST";
    case NT_DHCP_DECLINE:  return "DECLINE";
    case NT_DHCP_ACK:      return "ACK";
    case NT_DHCP_NAK:      return "NAK";
    case NT_DHCP_RELEASE:  return "RELEASE";
    case NT_DHCP_INFORM:   return "INFORM";
    default:               return "?";
    }
}

nt_status nt_dhcp_decode(const uint8_t *buf, size_t len, nt_dhcp *out)
{
    if (buf == NULL || out == NULL)
        return NT_ERR_MALFORMED;
    memset(out, 0, sizeof *out);

    if (len < NT_DHCP_MIN_LEN)
        return NT_ERR_TRUNCATED;
    if (rd32(buf, 236) != NT_DHCP_MAGIC)
        return NT_ERR_MALFORMED;

    out->op    = buf[0];
    out->htype = buf[1];
    out->hlen  = buf[2];
    out->hops  = buf[3];
    out->xid   = rd32(buf, 4);
    out->secs  = rd16(buf, 8);
    out->flags = rd16(buf, 10);
    out->ciaddr = rd32(buf, 12);
    out->yiaddr = rd32(buf, 16);
    out->siaddr = rd32(buf, 20);
    out->giaddr = rd32(buf, 24);
    memcpy(out->chaddr, buf + 28, 16);
    out->broadcast = (out->flags & NT_DHCP_FLAG_BROADCAST) != 0;
    out->buf = buf;
    out->len = len;

    /* htype 1 (Ethernet) requires hlen 6; hlen is never above 16 (rule 35). */
    if (out->hlen > 16)
        return NT_ERR_MALFORMED;
    if (out->htype == 1 && out->hlen != 6)
        return NT_ERR_MALFORMED;

    uint16_t seen[64];
    size_t nseen = 0;
    int have_end = 0;
    size_t off = NT_DHCP_MIN_LEN;

    while (off < len) {
        uint8_t code = buf[off];
        if (code == NT_DHCP_OPT_PAD) {
            off++;
            continue;
        }
        if (code == NT_DHCP_OPT_END) {
            have_end = 1;
            off++;
            break;
        }
        if (!need(len, off + 1, 1))
            return NT_ERR_MALFORMED;          /* code with no length octet */
        uint8_t olen = buf[off + 1];
        size_t dstart = off + 2;
        if (!need(len, dstart, olen))
            return NT_ERR_MALFORMED;          /* option length past the end */
        const uint8_t *d = buf + dstart;

        for (size_t i = 0; i < nseen; i++)
            if (seen[i] == code)
                return NT_ERR_MALFORMED;      /* a repeated option */
        if (nseen < sizeof seen / sizeof seen[0])
            seen[nseen++] = code;

        switch (code) {
        case NT_DHCP_OPT_MSG_TYPE:
            if (olen != 1 || d[0] < 1 || d[0] > 8)
                return NT_ERR_MALFORMED;
            out->has_msg_type = 1;
            out->msg_type = d[0];
            break;
        case NT_DHCP_OPT_SERVER_ID:
            if (olen != 4)
                return NT_ERR_MALFORMED;
            out->has_server_id = 1;
            out->server_id = rd32(buf, dstart);
            break;
        case NT_DHCP_OPT_REQUESTED_IP:
            if (olen != 4)
                return NT_ERR_MALFORMED;
            out->has_requested = 1;
            out->requested_ip = rd32(buf, dstart);
            break;
        case NT_DHCP_OPT_LEASE_TIME:
            if (olen != 4)
                return NT_ERR_MALFORMED;
            out->has_lease = 1;
            out->lease_time = rd32(buf, dstart);
            break;
        case NT_DHCP_OPT_T1:
            if (olen != 4)
                return NT_ERR_MALFORMED;
            out->has_t1 = 1;
            out->t1 = rd32(buf, dstart);
            break;
        case NT_DHCP_OPT_T2:
            if (olen != 4)
                return NT_ERR_MALFORMED;
            out->has_t2 = 1;
            out->t2 = rd32(buf, dstart);
            break;
        case NT_DHCP_OPT_MASK:
            if (olen != 4)
                return NT_ERR_MALFORMED;
            out->has_mask = 1;
            out->mask = rd32(buf, dstart);
            break;
        case NT_DHCP_OPT_ROUTER:
            if (olen == 0 || olen % 4 != 0)
                return NT_ERR_MALFORMED;
            out->has_router = 1;
            out->nrouter = (unsigned)(olen / 4);
            for (unsigned i = 0; i < out->nrouter && i < NT_DHCP_MAX_ADDRS; i++)
                out->router[i] = rd32(buf, dstart + 4u * i);
            break;
        case NT_DHCP_OPT_DNS:
            if (olen == 0 || olen % 4 != 0)
                return NT_ERR_MALFORMED;
            out->has_dns = 1;
            out->ndns = (unsigned)(olen / 4);
            for (unsigned i = 0; i < out->ndns && i < NT_DHCP_MAX_ADDRS; i++)
                out->dns[i] = rd32(buf, dstart + 4u * i);
            break;
        case NT_DHCP_OPT_HOSTNAME:
            out->has_hostname = 1;
            escape_into(d, olen, out->hostname, sizeof out->hostname);
            break;
        case NT_DHCP_OPT_DOMAIN:
            out->has_domain = 1;
            escape_into(d, olen, out->domain, sizeof out->domain);
            break;
        case NT_DHCP_OPT_MESSAGE:
            out->has_message = 1;
            escape_into(d, olen, out->message, sizeof out->message);
            break;
        case NT_DHCP_OPT_OVERLOAD:
            /* RFC 2132 section 9.3: sname/file reuse is out of scope. */
            return NT_ERR_UNSUPPORTED;
        default:
            break;   /* unknown option: walked and ignored */
        }

        out->nopts++;
        off = dstart + olen;
    }

    if (!have_end)
        return NT_ERR_MALFORMED;              /* END required (rule 35) */

    return NT_OK;
}

static int chaddr_eq(const uint8_t a[16], const uint8_t b[6])
{
    return memcmp(a, b, 6) == 0;
}

nt_match nt_dhcp_match_offer(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6])
{
    if (m == NULL || chaddr == NULL)
        return NT_INVALID;
    if (m->htype == 1 && m->hlen != 6)
        return NT_INVALID;
    if (m->op != NT_DHCP_BOOTREPLY)
        return NT_NO_MATCH;
    if (m->xid != xid)
        return NT_NO_MATCH;
    if (!chaddr_eq(m->chaddr, chaddr))
        return NT_NO_MATCH;
    if (!m->has_msg_type || m->msg_type != NT_DHCP_OFFER)
        return NT_NO_MATCH;
    if (!m->has_server_id)
        return NT_NO_MATCH;
    if (m->yiaddr == 0)
        return NT_NO_MATCH;
    return NT_MATCH;
}

nt_match nt_dhcp_match_ack(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6],
                           uint32_t requested_ip)
{
    if (m == NULL || chaddr == NULL)
        return NT_INVALID;
    if (m->htype == 1 && m->hlen != 6)
        return NT_INVALID;
    if (m->op != NT_DHCP_BOOTREPLY)
        return NT_NO_MATCH;
    if (m->xid != xid)
        return NT_NO_MATCH;
    if (!chaddr_eq(m->chaddr, chaddr))
        return NT_NO_MATCH;
    if (!m->has_msg_type || m->msg_type != NT_DHCP_ACK)
        return NT_NO_MATCH;
    if (!m->has_server_id)
        return NT_NO_MATCH;
    if (m->yiaddr == 0 || m->yiaddr != requested_ip)
        return NT_NO_MATCH;
    return NT_MATCH;
}

nt_match nt_dhcp_match_nak(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6])
{
    if (m == NULL || chaddr == NULL)
        return NT_INVALID;
    if (m->htype == 1 && m->hlen != 6)
        return NT_INVALID;
    if (m->op != NT_DHCP_BOOTREPLY)
        return NT_NO_MATCH;
    if (m->xid != xid)
        return NT_NO_MATCH;
    if (!chaddr_eq(m->chaddr, chaddr))
        return NT_NO_MATCH;
    if (!m->has_msg_type || m->msg_type != NT_DHCP_NAK)
        return NT_NO_MATCH;
    return NT_MATCH;
}

nt_status nt_dhcp_build(const nt_dhcp_out *o, uint8_t *out, size_t cap, size_t *outlen)
{
    if (o == NULL || out == NULL || outlen == NULL)
        return NT_ERR_MALFORMED;
    if (cap < NT_DHCP_MIN_SEND)
        return NT_ERR_TRUNCATED;

    memset(out, 0, NT_DHCP_MIN_LEN);
    out[0] = o->op;
    out[1] = o->htype;
    out[2] = o->hlen;
    out[3] = o->hops;
    put32be(out + 4, o->xid);
    put16be(out + 8, o->secs);
    put16be(out + 10, o->flags);
    put32be(out + 12, o->ciaddr);
    put32be(out + 16, o->yiaddr);
    put32be(out + 20, o->siaddr);
    put32be(out + 24, o->giaddr);
    memcpy(out + 28, o->chaddr, 16);
    put32be(out + 236, NT_DHCP_MAGIC);

    size_t off = NT_DHCP_MIN_LEN;
    for (size_t i = 0; i < o->nopts; i++) {
        const nt_dhcp_opt *op = &o->opts[i];
        if (!need(cap, off, 2 + (size_t)op->len))
            return NT_ERR_TRUNCATED;
        out[off++] = (uint8_t)op->code;
        out[off++] = op->len;
        if (op->len > 0) {
            memcpy(out + off, op->data, op->len);
            off += op->len;
        }
    }
    if (!need(cap, off, 1))
        return NT_ERR_TRUNCATED;
    out[off++] = NT_DHCP_OPT_END;

    if (off < NT_DHCP_MIN_SEND) {
        memset(out + off, 0, NT_DHCP_MIN_SEND - off);
        off = NT_DHCP_MIN_SEND;
    }
    *outlen = off;
    return NT_OK;
}

nt_status nt_build_eth_ipv4_udp(uint8_t *out, size_t cap, size_t *outlen,
                                const uint8_t eth_src[6], const uint8_t eth_dst[6],
                                uint32_t sip, uint32_t dip,
                                uint16_t sport, uint16_t dport,
                                const uint8_t *payload, size_t plen)
{
    if (out == NULL || outlen == NULL || eth_src == NULL || eth_dst == NULL)
        return NT_ERR_MALFORMED;
    if (plen > 0 && payload == NULL)
        return NT_ERR_MALFORMED;

    size_t udplen = 8 + plen;
    size_t iplen  = 20 + udplen;
    size_t framelen = 14 + iplen;
    if (framelen > 0xffff)
        return NT_ERR_MALFORMED;
    if (cap < framelen)
        return NT_ERR_TRUNCATED;

    memcpy(out, eth_dst, 6);
    memcpy(out + 6, eth_src, 6);
    put16be(out + 12, NT_ETHERTYPE_IPV4);

    uint8_t *ip = out + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45;                       /* version 4, IHL 5 */
    put16be(ip + 2, (uint16_t)iplen);
    ip[8] = 64;                         /* TTL */
    ip[9] = NT_IPPROTO_UDP;
    put32be(ip + 12, sip);
    put32be(ip + 16, dip);
    put16be(ip + 10, nt_csum_final(nt_csum_partial(ip, 20)));

    uint8_t *udp = ip + 20;
    put16be(udp, sport);
    put16be(udp + 2, dport);
    put16be(udp + 4, (uint16_t)udplen);
    put16be(udp + 6, 0);
    if (plen > 0)
        memcpy(udp + 8, payload, plen);

    uint32_t sum = nt_csum_pseudo4(sip, dip, NT_IPPROTO_UDP, (uint16_t)udplen);
    sum = nt_csum_add(sum, udp, udplen);
    uint16_t c = nt_csum_final(sum);
    put16be(udp + 6, c == 0 ? 0xffff : c);

    *outlen = framelen;
    return NT_OK;
}

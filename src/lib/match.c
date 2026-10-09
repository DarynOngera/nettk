/*
 * Reply matchers (M2). Pure: no I/O.
 *
 * A probe is matched only when it answers *our* echo: right type/code, valid
 * checksum, our identifier and sequence, the expected source, and (when we sent
 * a payload) an identical payload. Anything malformed is INVALID, anything
 * well-formed but not ours is NO_MATCH.
 */
#include "nettk.h"

#include <string.h>

static int echo_fields(const nt_icmp *r, uint16_t *id, uint16_t *seq, const uint8_t **payload,
                       size_t *payload_len)
{
    if (r->rest.len < 4)
        return -1;
    *id = (uint16_t)((r->rest.data[0] << 8) | r->rest.data[1]);
    *seq = (uint16_t)((r->rest.data[2] << 8) | r->rest.data[3]);
    *payload = r->rest.data + 4;
    *payload_len = r->rest.len - 4;
    return 0;
}

static int payload_matches(const nt_echo_probe *p, const uint8_t *payload, size_t payload_len)
{
    if (p->data == NULL || p->datalen == 0)
        return 1;
    if (payload_len != p->datalen)
        return 0;
    return memcmp(payload, p->data, p->datalen) == 0;
}

nt_match nt_match_icmp_echo_reply(const nt_icmp *r, uint32_t src, const nt_echo_probe *p)
{
    if (r == NULL || p == NULL)
        return NT_INVALID;
    if (r->csum_state == NT_CSUM_INVALID)
        return NT_INVALID;
    if (r->type != 0 || r->code != 0)
        return NT_NO_MATCH;

    uint16_t id, seq;
    const uint8_t *payload;
    size_t payload_len;
    if (echo_fields(r, &id, &seq, &payload, &payload_len) != 0)
        return NT_INVALID;

    if (id != p->id || seq != p->seq)
        return NT_NO_MATCH;
    if (p->src != 0 && src != p->src)
        return NT_NO_MATCH;
    if (!payload_matches(p, payload, payload_len))
        return NT_NO_MATCH;
    return NT_MATCH;
}

nt_match nt_match_icmp6_echo_reply(const nt_icmp *r, const uint8_t src[16], const nt_echo_probe *p)
{
    if (r == NULL || p == NULL || src == NULL)
        return NT_INVALID;
    if (r->csum_state == NT_CSUM_INVALID)
        return NT_INVALID;
    if (r->type != 129 || r->code != 0) /* ICMPv6 Echo Reply */
        return NT_NO_MATCH;

    uint16_t id, seq;
    const uint8_t *payload;
    size_t payload_len;
    if (echo_fields(r, &id, &seq, &payload, &payload_len) != 0)
        return NT_INVALID;

    if (id != p->id || seq != p->seq)
        return NT_NO_MATCH;
    if (!payload_matches(p, payload, payload_len))
        return NT_NO_MATCH;
    (void)src; /* IPv6 source is checked by the caller against the target */
    return NT_MATCH;
}

nt_status nt_icmp_quote_parse(const nt_icmp *err, nt_quote *out)
{
    if (err == NULL || out == NULL)
        return NT_ERR_MALFORMED;
    memset(out, 0, sizeof *out);

    /* ICMP bytes 8.. (rest offset 4) hold the quoted IPv4 packet. */
    if (err->rest.len < 4)
        return NT_ERR_TRUNCATED;
    const uint8_t *q = err->rest.data + 4;
    size_t qlen = err->rest.len - 4;

    if (!need(qlen, 0, 20))
        return NT_ERR_TRUNCATED;
    if ((rd8(q, 0) >> 4) != 4)
        return NT_ERR_MALFORMED;
    size_t hsize = (size_t)(rd8(q, 0) & 0x0f) * 4;
    if (hsize < 20)
        return NT_ERR_MALFORMED;
    if (!need(qlen, hsize, 8))
        return NT_ERR_TRUNCATED;

    out->proto = rd8(q, 9);
    out->src = rd32be(q, 12);
    out->dst = rd32be(q, 16);
    const uint8_t *l4 = q + hsize;
    if (out->proto == NT_IPPROTO_ICMP || out->proto == NT_IPPROTO_ICMPV6) {
        /* Quoted echo header: type(0) code(1) csum(2) id(4) seq(6). */
        out->id = rd16be(l4, 4);
        out->seq = rd16be(l4, 6);
    } else if (out->proto == NT_IPPROTO_UDP || out->proto == NT_IPPROTO_TCP) {
        out->sport = rd16be(l4, 0);
        out->dport = rd16be(l4, 2);
    }
    return NT_OK;
}

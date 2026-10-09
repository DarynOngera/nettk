#include "nettk.h"

#include <string.h>

static nt_status dispatch_ipv4(nt_packet *out, const uint8_t *l3, size_t l3len, const uint8_t *base)
{
    nt_status s = nt_ipv4_decode(l3, l3len, &out->ip4);
    if (s != NT_OK) {
        return s;
    }
    out->has_ipv4 = 1;
    out->l4_off = out->l3_off + (size_t)out->ip4.ihl * 4;
    out->payload_off = (size_t)(out->ip4.payload.data - base);
    out->payload_len = out->ip4.payload.len;

    if (!out->ip4.has_l4) {
        return NT_OK; /* non-first fragment: stop at L3, no reassembly */
    }

    const uint8_t *l4 = out->ip4.payload.data;
    size_t l4len = out->ip4.payload.len;
    nt_pseudo ph;
    memset(&ph, 0, sizeof ph);
    ph.family = 4;
    ph.src4 = out->ip4.src;
    ph.dst4 = out->ip4.dst;

    switch (out->ip4.proto) {
    case NT_IPPROTO_TCP:
        s = nt_tcp_decode(l4, l4len, &ph, &out->tcp);
        if (s == NT_OK) { out->has_tcp = 1; out->payload_off = (size_t)(out->tcp.payload.data - base); out->payload_len = out->tcp.payload.len; }
        return s;
    case NT_IPPROTO_UDP:
        s = nt_udp_decode(l4, l4len, &ph, &out->udp);
        if (s == NT_OK) { out->has_udp = 1; out->payload_off = (size_t)(out->udp.payload.data - base); out->payload_len = out->udp.payload.len; }
        return s;
    case NT_IPPROTO_ICMP:
        s = nt_icmp_decode(l4, l4len, &out->icmp);
        if (s == NT_OK) { out->has_icmp = 1; }
        return s;
    default:
        return NT_OK; /* unknown transport: stop at L3 */
    }
}

static nt_status dispatch_ipv6(nt_packet *out, const uint8_t *l3, size_t l3len, const uint8_t *base)
{
    nt_status s = nt_ipv6_decode(l3, l3len, &out->ip6);
    if (s != NT_OK) {
        return s;
    }
    out->has_ipv6 = 1;
    out->l4_off = out->l3_off + 40;
    out->payload_off = (size_t)(out->ip6.payload.data - base);
    out->payload_len = out->ip6.payload.len;

    uint8_t nxt = out->ip6.next_hdr;
    if (nxt == NT_IPPROTO_HOPOPTS || nxt == NT_IPPROTO_ROUTING ||
        nxt == NT_IPPROTO_FRAGMENT || nxt == NT_IPPROTO_DSTOPTS) {
        if (nxt == NT_IPPROTO_FRAGMENT) {
            out->ip6.is_fragment = 1;
        }
        return NT_ERR_UNSUPPORTED; /* extension-header chains are out of scope */
    }

    const uint8_t *l4 = out->ip6.payload.data;
    size_t l4len = out->ip6.payload.len;
    nt_pseudo ph;
    memset(&ph, 0, sizeof ph);
    ph.family = 6;
    memcpy(ph.src6, out->ip6.src, 16);
    memcpy(ph.dst6, out->ip6.dst, 16);

    switch (nxt) {
    case NT_IPPROTO_TCP:
        s = nt_tcp_decode(l4, l4len, &ph, &out->tcp);
        if (s == NT_OK) { out->has_tcp = 1; out->payload_off = (size_t)(out->tcp.payload.data - base); out->payload_len = out->tcp.payload.len; }
        return s;
    case NT_IPPROTO_UDP:
        s = nt_udp_decode(l4, l4len, &ph, &out->udp);
        if (s == NT_OK) { out->has_udp = 1; out->payload_off = (size_t)(out->udp.payload.data - base); out->payload_len = out->udp.payload.len; }
        return s;
    case NT_IPPROTO_ICMPV6:
        s = nt_icmp6_decode(l4, l4len, &ph, &out->icmpv6);
        if (s == NT_OK) { out->has_icmpv6 = 1; }
        return s;
    default:
        return NT_OK; /* unknown next header: stop at L3 */
    }
}

nt_status nt_decode_frame(const uint8_t *buf, size_t len, nt_packet *out)
{
    memset(out, 0, sizeof *out);

    nt_status s = nt_eth_decode(buf, len, &out->eth, &out->vlan);
    if (s != NT_OK && s != NT_ERR_UNSUPPORTED) {
        out->status = s;
        return s;
    }
    out->has_eth = 1;
    out->has_vlan = out->vlan.count > 0;
    out->l2_off = 0;
    out->l3_off = out->vlan.l3_off;
    if (s != NT_OK) {
        out->status = s;
        return s; /* 802.3 length field: stop at L2 */
    }

    const uint8_t *l3 = buf + out->l3_off;
    size_t l3len = len - out->l3_off;
    switch (out->vlan.inner_ethertype) {
    case NT_ETHERTYPE_ARP:
        s = nt_arp_decode(l3, l3len, &out->arp);
        if (s == NT_OK) { out->has_arp = 1; }
        break;
    case NT_ETHERTYPE_IPV4:
        s = dispatch_ipv4(out, l3, l3len, buf);
        break;
    case NT_ETHERTYPE_IPV6:
        s = dispatch_ipv6(out, l3, l3len, buf);
        break;
    default:
        s = NT_OK; /* unknown ethertype is not a decode error */
        break;
    }

    out->status = s;
    return s;
}

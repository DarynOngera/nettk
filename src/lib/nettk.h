/*
 * nettk: decode library public interface.
 *
 * Pure declarations and fixed-layout result structs. No I/O, no allocation, no globals.
 * Every decoder takes (const uint8_t *buf, size_t len) and returns an nt_status.
 * Payload slices are non-owning views into the caller's buffer; they are valid only
 * while that buffer is alive.
 */
#ifndef NETTK_H
#define NETTK_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    NT_OK = 0,
    NT_ERR_TRUNCATED,   /* buffer shorter than a header/length claims */
    NT_ERR_MALFORMED,   /* length/field violates a protocol rule */
    NT_ERR_UNSUPPORTED, /* well-formed but out of this phase's scope */
} nt_status;

#define NT_ETHERTYPE_IPV4 0x0800u
#define NT_ETHERTYPE_ARP  0x0806u
#define NT_ETHERTYPE_IPV6 0x86ddu

#define NT_IPPROTO_HOPOPTS  0
#define NT_IPPROTO_ICMP     1
#define NT_IPPROTO_TCP      6
#define NT_IPPROTO_UDP      17
#define NT_IPPROTO_ROUTING  43
#define NT_IPPROTO_FRAGMENT 44
#define NT_IPPROTO_ICMPV6   58
#define NT_IPPROTO_DSTOPTS  60

const char *nt_status_str(nt_status s);

/* overflow-safe bounds check: true iff off <= len && n <= len - off */
int need(size_t len, size_t off, size_t n);

/* precondition: need() already returned true for the read */
uint8_t  rd8(const uint8_t *buf, size_t off);
uint16_t rd16be(const uint8_t *buf, size_t off);
uint32_t rd32be(const uint8_t *buf, size_t off);

typedef struct { const uint8_t *data; size_t len; } nt_slice;

typedef enum { NT_CSUM_NOT_CHECKED, NT_CSUM_VALID, NT_CSUM_INVALID } nt_csum_state;

typedef struct {
    uint8_t  dst[6], src[6];
    uint16_t ethertype;   /* raw type at offset 12:2, e.g. 0x8100 on a tagged frame */
} nt_eth_hdr;

typedef struct {
    uint16_t tpid;        /* 0x8100 or 0x88a8 */
    uint16_t vid;         /* 0..4095 */
    uint8_t  pcp;         /* 0..7 */
    uint8_t  dei;
} nt_vlan_tag;

typedef struct {
    int         count;            /* 0..2 tags, outer first */
    nt_vlan_tag tag[2];
    uint16_t    inner_ethertype;  /* type after the tags; used for L3 dispatch */
    size_t      l3_off;           /* 14 + 4*count */
} nt_vlan;

typedef struct {
    uint16_t htype, ptype, op;
    uint8_t  hlen, plen;
    uint8_t  sha[6], spa[4], tha[6], tpa[4];
} nt_arp;

typedef struct {
    uint8_t  ihl;                 /* 32-bit words */
    uint8_t  tos, ttl, proto;
    uint16_t totlen, id, frag_off;
    uint8_t  flag_df, flag_mf;
    uint32_t src, dst;            /* host order */
    nt_slice options;
    nt_slice payload;
    int      is_fragment;         /* flag_mf || frag_off != 0 */
    int      has_l4;              /* frag_off == 0 */
    nt_csum_state hdr_csum;
} nt_ipv4;

typedef struct {
    uint16_t payload_len;
    uint8_t  next_hdr, hop_limit;
    uint8_t  src[16], dst[16];
    nt_slice payload;
    int      is_fragment;
} nt_ipv6;

typedef struct {
    uint16_t sport, dport, window, csum, urg;
    uint32_t seq, ack;
    uint8_t  data_off;            /* 32-bit words */
    uint16_t flags;               /* NS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN */
    nt_slice options, payload;
    int      mss, wscale, sack_ok;
    uint32_t ts_val, ts_ecr;
    int      has_ts;
    nt_csum_state csum_state;
} nt_tcp;

typedef struct {
    uint16_t sport, dport, len, csum;
    nt_slice payload;
    nt_csum_state csum_state;
} nt_udp;

typedef struct {
    uint8_t  type, code;
    uint16_t csum;
    nt_slice rest;
    uint8_t  target[16];          /* ICMPv6 NS/NA target address (has_target) */
    int      has_target;
    nt_csum_state csum_state;
} nt_icmp;

typedef struct {
    int      has_eth, has_vlan, has_arp, has_ipv4, has_ipv6, has_tcp, has_udp, has_icmp, has_icmpv6;
    nt_eth_hdr eth;
    nt_vlan    vlan;
    nt_arp     arp;
    nt_ipv4    ip4;
    nt_ipv6    ip6;
    nt_tcp     tcp;
    nt_udp     udp;
    nt_icmp    icmp;
    nt_icmp    icmpv6;
    size_t     l2_off, l3_off, l4_off, payload_off, payload_len;
    nt_status  status;            /* deepest failure, or NT_OK */
} nt_packet;

/* L2 */
nt_status nt_eth_decode(const uint8_t *buf, size_t len, nt_eth_hdr *eth, nt_vlan *vlan);

/* pseudo-header context for L4 checksum verification */
typedef struct {
    int      family;             /* 4 or 6 */
    uint32_t src4, dst4;         /* host order, family 4 */
    uint8_t  src6[16], dst6[16]; /* family 6 */
} nt_pseudo;

/* L3 */
nt_status nt_arp_decode(const uint8_t *buf, size_t len, nt_arp *out);
nt_status nt_ipv4_decode(const uint8_t *buf, size_t len, nt_ipv4 *out);
nt_status nt_ipv6_decode(const uint8_t *buf, size_t len, nt_ipv6 *out);

/* L4; ph may be NULL to skip checksum verification (state = NT_CSUM_NOT_CHECKED) */
nt_status nt_tcp_decode(const uint8_t *buf, size_t len, const nt_pseudo *ph, nt_tcp *out);
nt_status nt_udp_decode(const uint8_t *buf, size_t len, const nt_pseudo *ph, nt_udp *out);
nt_status nt_icmp_decode(const uint8_t *buf, size_t len, nt_icmp *out);
nt_status nt_icmp6_decode(const uint8_t *buf, size_t len, const nt_pseudo *ph, nt_icmp *out);

/* checksums: ones-complement, network order. sums are partial until nt_csum_final. */
uint32_t nt_csum_partial(const void *p, size_t n);
uint32_t nt_csum_add(uint32_t sum, const void *p, size_t n);
uint16_t nt_csum_final(uint32_t sum);
uint32_t nt_csum_pseudo4(uint32_t src, uint32_t dst, uint8_t proto, uint16_t l4len);
uint32_t nt_csum_pseudo6(const uint8_t src[16], const uint8_t dst[16], uint8_t nxt, uint32_t l4len);

/* top-level dispatcher: walks L2 -> VLAN -> L3 -> L4 as far as the frame allows */
nt_status nt_decode_frame(const uint8_t *buf, size_t len, nt_packet *out);

/*
 * Builders: pure, no I/O, bounds-checked. Checksums are computed here.
 * Return NT_ERR_TRUNCATED when cap is too small, NT_ERR_MALFORMED on invalid
 * arguments (NULL pointer where one is required). *outlen is the bytes written.
 */

/* ICMPv4 echo request (type 8) or reply (type 0). outlen = 8 + datalen. */
nt_status nt_build_icmp_echo(uint8_t *out, size_t cap, size_t *outlen,
                             uint8_t type, uint16_t id, uint16_t seq,
                             const uint8_t *data, size_t datalen);

typedef struct {
    uint8_t  eth_src[6], eth_dst[6]; /* Ethernet addresses (eth_dst = broadcast for a request) */
    uint16_t op;                     /* 1 request, 2 reply */
    uint8_t  sha[6], spa[4];         /* sender hardware/protocol */
    uint8_t  tha[6], tpa[4];         /* target hardware (zero for a request) / protocol */
} nt_arp_in;

/* Full Ethernet + ARP-for-IPv4 frame, 42 bytes. Minimum-frame padding is the
 * send path's concern (confirmed by capture at M7). */
nt_status nt_build_arp_frame(uint8_t *out, size_t cap, size_t *outlen, const nt_arp_in *in);

/* ICMPv6 neighbour solicitation. src_ll may be NULL to omit the source
 * link-layer option (DAD); the checksum uses the IPv6 pseudo-header over src/dst. */
nt_status nt_build_icmp6_ns(uint8_t *out, size_t cap, size_t *outlen,
                            const uint8_t src[16], const uint8_t dst[16],
                            const uint8_t target[16], const uint8_t src_ll[6]);

/* ICMPv6 echo request (128) or reply (129); checksum over the IPv6 pseudo-header. */
nt_status nt_build_icmp6_echo(uint8_t *out, size_t cap, size_t *outlen,
                              uint8_t type, uint16_t id, uint16_t seq,
                              const uint8_t *data, size_t datalen,
                              const uint8_t src[16], const uint8_t dst[16]);

/*
 * Reply matchers: pure, no I/O, fuzzable. NO_MATCH means "well-formed, not ours"
 * and is never an error; INVALID means the input could not be trusted.
 */
typedef enum { NT_MATCH = 0, NT_NO_MATCH = 1, NT_INVALID = 2 } nt_match;

typedef struct {
    uint16_t id, seq;
    uint32_t src;          /* expected source (host order); 0 = don't care */
    const uint8_t *data;   /* expected echo payload after id/seq, or NULL */
    size_t datalen;
} nt_echo_probe;

nt_match nt_match_icmp_echo_reply(const nt_icmp *r, uint32_t src, const nt_echo_probe *p);
nt_match nt_match_icmp6_echo_reply(const nt_icmp *r, const uint8_t src[16], const nt_echo_probe *p);

/* The IPv4 packet quoted inside an ICMPv4 error (RFC 792). */
typedef struct {
    uint8_t  proto;
    uint32_t src, dst;
    uint16_t sport, dport;  /* UDP/TCP */
    uint16_t id, seq;       /* ICMP */
} nt_quote;

/* Parse the quoted packet's header plus 8 bytes of L4. The original totlen
 * describes the whole packet, so only what is actually present is read. */
nt_status nt_icmp_quote_parse(const nt_icmp *err, nt_quote *out);

#endif /* NETTK_H */

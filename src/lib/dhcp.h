/*
 * DHCP (BOOTP) codec, builders and matchers for phase 6.
 *
 * Pure declarations and fixed-layout result structs. No I/O, no allocation,
 * no globals (AGENTS.md section 4). Every decoder takes (const uint8_t *buf,
 * size_t len) and returns an nt_status. `buf`/`len` in the result is a
 * non-owning view into the caller's UDP payload, valid only while it is alive.
 *
 * Wire format: RFC 2131 section 2 (message), RFC 2132 (options). The decoder
 * takes the DHCP message, i.e. the UDP payload (NOT including UDP/IP headers).
 */
#ifndef NT_DHCP_H
#define NT_DHCP_H

#include "nettk.h"

#include <stddef.h>
#include <stdint.h>

#define NT_DHCP_SERVER_PORT 67u
#define NT_DHCP_CLIENT_PORT 68u
#define NT_DHCP_MAGIC       0x63825363u /* 63 82 53 63 at offset 236 */

/* Minimum message that must be present: header + cookie (offset 240). */
#define NT_DHCP_MIN_LEN    240u
/* Clients must send at least 300 bytes of BOOTP payload (RFC 2131 section 2). */
#define NT_DHCP_MIN_SEND   300u

/* op */
#define NT_DHCP_BOOTREQUEST 1u
#define NT_DHCP_BOOTREPLY   2u

/* option 53 values (RFC 2132 section 9.6) */
enum {
    NT_DHCP_DISCOVER = 1,
    NT_DHCP_OFFER    = 2,
    NT_DHCP_REQUEST  = 3,
    NT_DHCP_DECLINE  = 4,
    NT_DHCP_ACK      = 5,
    NT_DHCP_NAK      = 6,
    NT_DHCP_RELEASE  = 7,
    NT_DHCP_INFORM   = 8,
};

/* option codes we look at (RFC 2132) */
enum {
    NT_DHCP_OPT_PAD             = 0,
    NT_DHCP_OPT_MASK            = 1,
    NT_DHCP_OPT_ROUTER          = 3,
    NT_DHCP_OPT_DNS             = 6,
    NT_DHCP_OPT_HOSTNAME        = 12,
    NT_DHCP_OPT_DOMAIN          = 15,
    NT_DHCP_OPT_REQUESTED_IP    = 50,
    NT_DHCP_OPT_LEASE_TIME      = 51,
    NT_DHCP_OPT_OVERLOAD        = 52, /* RFC 2132 section 9.3: out of scope */
    NT_DHCP_OPT_MSG_TYPE        = 53,
    NT_DHCP_OPT_SERVER_ID       = 54,
    NT_DHCP_OPT_PARAM_LIST      = 55,
    NT_DHCP_OPT_MESSAGE         = 56,
    NT_DHCP_OPT_MAX_MSG_SIZE    = 57,
    NT_DHCP_OPT_T1              = 58,
    NT_DHCP_OPT_T2              = 59,
    NT_DHCP_OPT_CLIENT_ID       = 61,
    NT_DHCP_OPT_END             = 255,
};

#define NT_DHCP_MAX_ADDRS 4
#define NT_DHCP_TEXT_MAX  65  /* escaped free text, NUL-terminated (rule 43) */

/* One option as prepared by a caller for a builder. */
typedef struct {
    uint16_t code;   /* low 8 bits are written; kept wide for convenience */
    uint8_t  len;
    uint8_t  data[255];
} nt_dhcp_opt;

/* Header flags (RFC 2131 section 2) */
#define NT_DHCP_FLAG_BROADCAST 0x8000u

typedef struct {
    /* fixed header, host order */
    uint8_t  op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t  chaddr[16];

    /* recognised options (the ones a client or printer cares about) */
    int      has_msg_type;  uint8_t  msg_type;
    int      has_server_id; uint32_t server_id;
    int      has_requested; uint32_t requested_ip;
    int      has_lease;     uint32_t lease_time;
    int      has_t1;        uint32_t t1;
    int      has_t2;        uint32_t t2;
    int      has_mask;      uint32_t mask;
    int      has_router;    uint32_t router[NT_DHCP_MAX_ADDRS]; unsigned nrouter;
    int      has_dns;       uint32_t dns[NT_DHCP_MAX_ADDRS];    unsigned ndns;
    int      has_hostname;  char     hostname[NT_DHCP_TEXT_MAX];
    int      has_domain;    char     domain[NT_DHCP_TEXT_MAX];
    int      has_message;   char     message[NT_DHCP_TEXT_MAX];

    unsigned nopts;          /* options successfully walked */
    int      broadcast;      /* flags bit 15 set */

    /* view of the whole payload (for printers that need sname/file) */
    const uint8_t *buf;
    size_t         len;
} nt_dhcp;

/* Decode a DHCP message (the UDP payload). See docs/phase6.md for the rule set:
 * < 240 bytes TRUNCATED; wrong cookie MALFORMED; htype 1 needs hlen 6; hlen > 16
 * MALFORMED; option 52 UNSUPPORTED; a repeated option MALFORMED; missing END
 * MALFORMED; per-option length and value checks per rule 36. */
nt_status nt_dhcp_decode(const uint8_t *buf, size_t len, nt_dhcp *out);

const char *nt_dhcp_msg_type_str(uint8_t type);
const char *nt_dhcp_op_str(uint8_t op);

/* Reply matchers (rule 38). INVALID means the message could not be trusted;
 * NO_MATCH means "well-formed, not ours" and is never an error. */
nt_match nt_dhcp_match_offer(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6]);
nt_match nt_dhcp_match_ack(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6],
                           uint32_t requested_ip);
nt_match nt_dhcp_match_nak(const nt_dhcp *m, uint32_t xid, const uint8_t chaddr[6]);

/* Builder: assemble a DHCP message from a fixed header plus caller options.
 * Appends END and zero-pads the payload to at least NT_DHCP_MIN_SEND bytes
 * (rule 37). Returns NT_ERR_TRUNCATED when cap is too small. */
typedef struct {
    uint8_t  op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t  chaddr[16];
    const nt_dhcp_opt *opts;
    size_t   nopts;
} nt_dhcp_out;

nt_status nt_dhcp_build(const nt_dhcp_out *o, uint8_t *out, size_t cap, size_t *outlen);

/* Full Ethernet + IPv4 + UDP frame around an already-built payload. Computes
 * the IPv4 header checksum and the UDP checksum over the pseudo-header. */
nt_status nt_build_eth_ipv4_udp(uint8_t *out, size_t cap, size_t *outlen,
                                const uint8_t eth_src[6], const uint8_t eth_dst[6],
                                uint32_t sip, uint32_t dip,
                                uint16_t sport, uint16_t dport,
                                const uint8_t *payload, size_t plen);

#endif /* NT_DHCP_H */
